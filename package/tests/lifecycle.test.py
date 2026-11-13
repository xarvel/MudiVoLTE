#!/usr/bin/env python3
"""Run the real lifecycle functions with fake modem/package-manager boundaries.

No router, root privileges or network needed. BusyBox ash when available,
otherwise /bin/sh. Absolute device/config paths are replaced before execution.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SHELL = [shutil.which("busybox"), "ash"] if shutil.which("busybox") else ["/bin/sh"]
SOURCE, DISPATCH = (ROOT / "package/files/usr/sbin/mudi-volte").read_text().split('\ncase "${1:-}" in\n', 1)
VERSION = (ROOT / "package/VERSION").read_text().strip()

STUBS = r'''
DATA=$SB/data
ORIG=$DATA/modem.orig
LPM_ORIG=$DATA/lpm.orig
SETUP_LOG=$SB/setup.log
SETUP_STATE=$SB/setup.state
SCREEN_PID=$SB/screen.pid
INIT=init_stub
IMSD=imsd_stub
DSI_HELPER=helper_stub
mkdir -p "$DATA"
init_stub() { echo "init $*" >>"$SB/events"; }
imsd_stub() { echo "qr" >>"$SB/events"; exec sleep "${QR_SECS:-0.05}"; }
helper_stub() { [ "$*" = check ] && [ "${LIBRARY:-available}" = available ]; }
screen_stub() { echo "screen $*" >>"$SB/events"; }
pidof() { return 1; }
ask() { [ "${AGREE:-yes}" = yes ]; }
check_device() { :; }
phone_users() { echo alpha; }
power_saving_off() { :; }
power_saving_restore() { :; }
modem_reboot() { echo reboot >>"$SB/events"; }
modem_sync() { echo "AT+QEFSSYNC=0" >>"$SB/at"; }
ims_mode() { [ "${MODE:-1}" = none ] || echo "${MODE:-1}"; }
voice_disable() { echo "${VD:-2}"; }
mode_pref() { echo AUTO; }
voice_domain() { echo "${VDOM:-3}"; }
ue_usage() { echo "${UE:-0}"; }
at() { echo 001010000000000; }
at_set() {
 echo "$1" >>"$SB/at"
 case "$1" in *"${FAIL_AT:-not-a-command}"*) return 1 ;; esac
 return 0
}
uci() {
 echo "uci $*" >>"$SB/events"
 case "$*" in
 *get*mudi-volte.main.country*) echo 44 ;;
 esac
}
opkg() { echo "opkg $*" >>"$SB/events"; return "${OPKG_RC:-0}"; }
'''


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mudi-lifecycle-")
        self.addCleanup(self.tmp.cleanup)
        self.sb = Path(self.tmp.name)
        # Replace even unused absolute paths: a mistake must not affect the host.
        src = SOURCE.replace("/etc/init.d/gl_screen", "screen_stub")
        src = src.replace("/etc/config/mudi-volte", str(self.sb / "config"))
        self.base = src + "\n" + STUBS

    def script(self, command, name="case.sh"):
        p = self.sb / name
        p.write_text(self.base + "\n" + command + "\n")
        return p

    def run_case(self, command, **env):
        return subprocess.run(SHELL + [str(self.script(command))],
                              env={**os.environ, "SB": str(self.sb), **env},
                              text=True, capture_output=True, timeout=10)

    def read(self, name):
        p = self.sb / name
        return p.read_text() if p.exists() else ""

    def saved(self):
        (self.sb / "data").mkdir(exist_ok=True)
        (self.sb / "data/modem.orig").write_text(
            "ims=1\nvoice_disable=2\nmode_pref=AUTO\nvoice_domain=3\nue_usage=0\n")

    def test_uninstall_without_backup_does_not_change_builtin_modem(self):
        r = self.run_case("restore_builtin remove", MODE="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read("at"), "")
        self.assertIn("opkg remove", self.read("events"))

    def test_restore_failure_preserves_package_and_backup(self):
        for failed in ('QCFG="ims"', 'voice_disable', 'voice_domain', 'ue_usage_setting'):
            with self.subTest(failed=failed):
                self.saved()
                (self.sb / "events").write_text("")
                r = self.run_case("restore_builtin remove", MODE="2", FAIL_AT=failed)
                self.assertNotEqual(r.returncode, 0)
                self.assertTrue((self.sb / "data/modem.orig").exists())
                self.assertNotIn("opkg", self.read("events"))
                self.assertNotIn("reboot", self.read("events"))

    def test_opkg_failure_preserves_settings(self):
        self.saved()
        r = self.run_case("restore_builtin remove", MODE="2", OPKG_RC="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue((self.sb / "data/modem.orig").exists())
        self.assertNotIn("reboot", self.read("events"))

    def test_cancelled_setup_stays_disabled(self):
        r = self.run_case("cmd_setup", AGREE="no")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("enabled=1", self.read("events"))
        self.assertEqual(self.read("at"), "")

    def test_refused_mode_switch_stays_disabled(self):
        r = self.run_case("cmd_setup", FAIL_AT='QCFG="ims",2')
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("enabled=1", self.read("events"))
        self.assertNotIn("reboot", self.read("events"))

    def test_successful_setup_enables_service(self):
        r = self.run_case("cmd_setup")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("enabled=1", self.read("events"))
        self.assertIn("reboot", self.read("events"))

    def test_external_without_backup_uses_factory_voice_defaults(self):
        r = self.run_case("save_orig", MODE="2", VDOM="1", UE="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        saved = self.read("data/modem.orig")
        self.assertIn("voice_domain=3\n", saved)
        self.assertIn("ue_usage=0\n", saved)

    def test_init_keeps_each_allowed_number_as_one_value(self):
        init = (ROOT / "package/files/etc/init.d/mudi-volte").read_text()
        init = init.replace(". /usr/share/libubox/jshn.sh", "")
        command = init + r'''
config_get() { eval "$1=\$4"; }
config_get_bool() { config_get "$@"; }
config_foreach() { :; }
config_list_foreach() {
 [ "$2" = allow ] || return 0
 "$3" '+44 7700 900123' "${4:-}"
 "$3" '+1 (555) 100-2222' "${4:-}"
}
json_init() { :; }
json_add_array() { array=$1; }
json_close_array() { array=; }
json_add_string() { [ "$array" != allow ] || printf '%s\n' "$2" >>"$SB/allowed"; }
json_add_object() { :; }
json_close_object() { :; }
json_add_int() { :; }
json_add_boolean() { :; }
json_dump() { :; }
build_config
'''
        r = self.run_case(command)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read("allowed").splitlines(),
                         ['+44 7700 900123', '+1 (555) 100-2222'])

    def test_setup_requires_the_dsi_api(self):
        for library in ("available", "missing", "missing-symbol"):
            with self.subTest(library=library):
                r = self.run_case("check_data_call", LIBRARY=library)
                self.assertEqual(r.returncode, 0 if library == "available" else 1, r.stderr)
                if library != "available":
                    self.assertIn("cannot load the firmware's DSI API", r.stderr)
                    self.assertEqual(self.read("at"), "")

    def test_qr_handoff_restores_screen_only_after_last_code(self):
        first = subprocess.Popen(SHELL + [str(self.script("screen_loop alpha 30 url", "first.sh"))],
                                 env={**os.environ, "SB": str(self.sb), "QR_SECS": "10"},
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: first.poll() is None and first.terminate())
        for _ in range(100):
            if "qr" in self.read("events"):
                break
            time.sleep(0.01)
        self.assertIn("qr", self.read("events"))
        second = self.run_case("screen_loop beta 1 url", QR_SECS="0.05")
        first.wait(timeout=3)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.read("events").splitlines(),
                         ["screen stop", "qr", "qr", "screen start"])
        self.assertFalse((self.sb / "screen.pid").exists())


def swap(text, old, new):
    assert old in text, old  # a stub that silently stays the old one tests nothing
    return text.replace(old, new)


# opkg as opkg-lede (OpenWrt 23.05) runs the maintainer scripts, on files in
# the sandbox (libopkg/opkg_cmd.c, opkg_remove.c, opkg_install.c):
# - remove: 'prerm remove', PKG_UPGRADE=0; when it fails the package stays,
#   unless --force-remove. Then the files go (an edited conffile stays) and
#   'postrm remove' runs.
# - install --force-reinstall: the whole removal first, its result ignored,
#   then a fresh install.
# - install of another version: 'prerm upgrade NEW' and 'postrm upgrade NEW'
#   of the installed package, PKG_UPGRADE=1.
FAKE_OPKG = r'''
echo "opkg $*" >>"$SB/events"
[ -z "${MUDI_VOLTE_REINSTALL:-}" ] || echo "reinstall mark" >>"$SB/events"
force_remove=0 reinstall=0 cmd='' file=''
for a in "$@"; do
 case "$a" in
 --force-remove) force_remove=1 ;;
 --force-reinstall) reinstall=1 ;;
 -*) ;;
 *) if [ -z "$cmd" ]; then cmd=$a; else file=$a; fi ;;
 esac
done
installed=$(cat "$SB/installed" 2>/dev/null)
remove() {
 [ -n "$installed" ] || return 0
 if ! PKG_UPGRADE=0 "$SB/info/prerm" remove && [ "$force_remove" != 1 ]; then
  echo 'not removing package "mudi-volte", prerm script failed' >&2
  return 1
 fi
 rm -f "$SB/cli" "$SB/installed"
 installed=''
 PKG_UPGRADE=0 "$SB/info/postrm" remove
}
case "$cmd" in
list-installed) [ -z "$installed" ] || echo "mudi-volte - $installed" ;;
remove) remove || exit 255 ;;
install)
 new=$(basename "$file" | sed -n 's/^mudi-volte_\(.*\)_aarch64_cortex-a53\.ipk$/\1-1/p')
 [ "$reinstall" = 1 ] && remove
 if [ "$installed" = "$new" ]; then
  echo "Package mudi-volte ($new) installed in root is up to date."
  exit 0
 fi
 upgrade=0
 if [ -n "$installed" ]; then
  PKG_UPGRADE=1 "$SB/info/prerm" upgrade "$new" || exit 255
  PKG_UPGRADE=1 "$SB/info/postrm" upgrade "$new" || exit 255
  upgrade=1
 fi
 cp "$SB/cli.pkg" "$SB/cli"
 echo "$new" >"$SB/installed"
 echo "postinst configure PKG_UPGRADE=$upgrade" >>"$SB/events"
 ;;
esac
'''

# What setup leaves: the modem in External VoLTE mode with IMS-only voice, the
# values from before in modem.orig.
EXTERNAL = {"MODE": "2", "VD": "3", "VDOM": "1", "UE": "1"}
# The restore of the values saved by setup, then their commit to the modem's flash.
WRITES = ['AT+QCFG="ims",1', 'AT+QCALLCFG="voice_disable",2',
          'AT+QNWPREFCFG="voice_domain",3', 'AT+QNWPREFCFG="ue_usage_setting",0']
GIVE_BACK = WRITES + ['AT+QEFSSYNC=0']


class RawPackageRemoval(unittest.TestCase):
    """opkg remove (LuCI > System > Software > Remove, the GL plugin page, opkg
    over SSH) without 'mudi-volte uninstall', and the other ways opkg runs the
    package's prerm and postrm: a reinstall, an upgrade, 'mudi-volte uninstall'.
    The real maintainer scripts and the real CLI, with the modem, uci, init and
    opkg replaced. No terminal: LuCI runs opkg without one."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mudi-removal-")
        self.addCleanup(self.tmp.cleanup)
        self.sb = sb = Path(self.tmp.name)
        (sb / "data").mkdir()
        (sb / "data/modem.orig").write_text(
            "ims=1\nvoice_disable=2\nmode_pref=AUTO\nvoice_domain=3\nue_usage=0\n")
        (sb / "data/push.json").write_text("[]\n")
        (sb / "config").write_text("config voip 'main'\n\toption enabled '1'\n")
        (sb / "run").mkdir()
        (sb / "run/imsd.json").write_text("{}\n")
        (sb / "installed").write_text(VERSION + "-1\n")
        (sb / "info").mkdir()
        for name in ("prerm", "postrm"):
            self.executable("info/" + name, self.maintainer_script(name))
        self.executable("cli.pkg", self.cli())
        shutil.copy(sb / "cli.pkg", sb / "cli")
        (sb / "bin").mkdir()
        self.executable("bin/opkg", FAKE_OPKG)

    def executable(self, name, body):
        p = self.sb / name
        p.write_text("#!" + " ".join(SHELL) + "\n" + body)
        p.chmod(0o755)

    def maintainer_script(self, name):
        s = (ROOT / "package/control" / name).read_text()
        for a, b in (("/var/run/mudi-volte-removal", "$SB/removal"),
                     ("/var/run/mudi-volte", "$SB/run"),
                     ("/usr/sbin/mudi-volte", "$SB/cli"),
                     ("/etc/init.d/mudi-volte", "init_stub"),
                     ("/etc/init.d/firewall", "true"),
                     ("/etc/init.d/nginx", "true"),
                     ("/etc/config/mudi-volte", "$SB/config"),
                     ("/etc/mudi-volte", "$SB/data"),
                     ("/tmp/luci-indexcache", "$SB/luci-indexcache"),
                     ("/tmp/luci-modulecache", "$SB/luci-modulecache"),
                     ("/www/luci-static/resources/view/mudi-volte", "$SB/view")):
            s = s.replace(a, b)
        body = s.split("\n", 1)[1]
        for host in ("/etc/", "/var/", "/usr/", "/tmp/", "/www/"):
            assert host not in body, (name, host)  # nothing on the host but /proc, read only
        head = r'''
init_stub() { echo "init $*" >>"$SB/events"; }
fw4() { echo "fw4 $*" >>"$SB/events"; }
nginx() { echo "nginx $*" >>"$SB/events"; }
'''
        return head + body

    def cli(self):
        """The CLI with the stubs of Lifecycle, as an executable file; the real
        ask, which records each question."""
        src = SOURCE.replace("/etc/init.d/gl_screen", "screen_stub")
        src = src.replace("/etc/config/mudi-volte", str(self.sb / "config"))
        src = swap(src, "\nask() {", "\nreal_ask() {")
        stubs = swap(STUBS, 'ask() { [ "${AGREE:-yes}" = yes ]; }',
                     'ask() { echo ask >>"$SB/events"; real_ask "$@"; }')
        stubs = swap(stubs, "power_saving_restore() { :; }",
                     'power_saving_restore() { echo "sleep restored" >>"$SB/events"; }')
        stubs = swap(stubs, 'opkg() { echo "opkg $*" >>"$SB/events"; return "${OPKG_RC:-0}"; }',
                     'opkg() { "$SB/bin/opkg" "$@"; }')
        return src + "\n" + stubs + '\ncase "${1:-}" in\n' + DISPATCH

    def run_sh(self, args, path=None, **env):
        env = {**os.environ, "SB": str(self.sb), **EXTERNAL, **env}
        if path:
            env["PATH"] = path + os.pathsep + env["PATH"]
        return subprocess.run(args, env=env, text=True, capture_output=True, timeout=30,
                              stdin=subprocess.DEVNULL, start_new_session=True)

    def opkg(self, *args, **env):
        return self.run_sh([str(self.sb / "bin/opkg"), *args], **env)

    def read(self, name):
        p = self.sb / name
        return p.read_text() if p.exists() else ""

    def events(self):
        return self.read("events").splitlines()

    def assertKept(self):
        self.assertEqual(self.read("at"), "", "the modem was touched")
        self.assertTrue((self.sb / "data/modem.orig").exists())
        self.assertTrue((self.sb / "data/push.json").exists())
        self.assertTrue((self.sb / "config").exists())
        self.assertNotIn("uci -q set mudi-volte.main.enabled=0", self.events())
        self.assertNotIn("ask", self.events())

    def ipk(self, version):
        p = self.sb / ("mudi-volte_%s_aarch64_cortex-a53.ipk" % version)
        p.write_bytes(b"not a real package " + version.encode())
        return p

    def test_remove_does_not_strand_the_modem_in_external_mode(self):
        # The router after setup: the modem in External VoLTE mode with
        # voice_domain=1, the service on. opkg runs the scripts for a removal.
        pre = self.run_sh([str(self.sb / "info/prerm"), "remove"])
        post = self.run_sh([str(self.sb / "info/postrm"), "remove"])
        at = self.read("at")
        self.assertTrue(
            pre.returncode != 0 or 'QCFG="ims",1' in at,
            "opkg remove went through (prerm %d, postrm %d) with the modem untouched (AT: %r): "
            "it stays in External VoLTE mode with voice_domain=1 and no IMS client, so no calls "
            "reach the SIM; events: %r" % (pre.returncode, post.returncode, at, self.events()))

    def test_removal_gives_the_modem_back_and_removes_the_data(self):
        r = self.opkg("--autoremove", "remove", "mudi-volte")  # as LuCI runs it
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read("at").splitlines(), GIVE_BACK)
        ev = self.events()
        for e in ("init stop", "init disable", "uci -q set mudi-volte.main.enabled=0", "sleep restored"):
            self.assertIn(e, ev)
        self.assertNotIn("reboot", ev)  # opkg and the web page have to finish first
        self.assertNotIn("ask", ev)
        self.assertFalse((self.sb / "data").exists())
        self.assertFalse((self.sb / "config").exists())
        self.assertFalse((self.sb / "run").exists())
        self.assertFalse((self.sb / "installed").exists())
        self.assertIn("Restart the router", r.stdout)

    def test_removal_commits_the_modem_settings_to_its_flash(self):
        # The modem saves a value written by an AT command only 90 s later. A
        # removal does not restart the router; the user does, from LuCI or by
        # the power button, perhaps within seconds, and without the commit the
        # modem comes back in External VoLTE mode with no client.
        r = self.opkg("--autoremove", "remove", "mudi-volte")
        self.assertEqual(r.returncode, 0, r.stderr)
        at = self.read("at").splitlines()
        self.assertIn("AT+QEFSSYNC=0", at, "the restored values are not committed: %r" % at)
        self.assertEqual(at[-1], "AT+QEFSSYNC=0", "a value is written after the commit: %r" % at)

    def test_refused_restore_commits_nothing(self):
        # The values set back after a refusal are the ones the modem holds; no
        # commit, so that nothing of the half restore can outlive a restart.
        r = self.opkg("remove", "mudi-volte", FAIL_AT="voice_domain")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("AT+QEFSSYNC=0", self.read("at").splitlines())

    def test_removal_of_a_package_never_set_up(self):
        (self.sb / "data/modem.orig").unlink()
        r = self.opkg("remove", "mudi-volte", MODE="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read("at"), "")  # setup never switched the modem
        self.assertNotIn("Restart", r.stdout)
        self.assertFalse((self.sb / "data").exists())
        self.assertFalse((self.sb / "config").exists())

    def test_unanswering_modem_refuses_the_removal(self):
        r = self.opkg("--autoremove", "remove", "mudi-volte", MODE="none")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not answering", r.stderr)
        self.assertIn("mudi-volte uninstall", r.stderr)
        self.assertIn("opkg remove --force-remove", r.stderr)
        self.assertKept()
        ev = self.events()
        self.assertFalse([e for e in ev if e.startswith("init ")], ev)  # the line keeps working
        self.assertTrue((self.sb / "installed").exists())

    def test_refused_value_is_set_back_and_the_removal_refused(self):
        r = self.opkg("remove", "mudi-volte", FAIL_AT="voice_domain")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("mudi-volte uninstall", r.stderr)
        # Written, refused, then the External VoLTE values back, newest first.
        self.assertEqual(self.read("at").splitlines(),
                         GIVE_BACK[:3] + ['AT+QCALLCFG="voice_disable",3', 'AT+QCFG="ims",2'])
        ev = self.events()
        self.assertFalse([e for e in ev if e.startswith("init ")], ev)
        self.assertNotIn("uci -q set mudi-volte.main.enabled=0", ev)
        self.assertTrue((self.sb / "data/modem.orig").exists())
        self.assertTrue((self.sb / "config").exists())

    def test_forced_removal_warns_and_keeps_the_data(self):
        r = self.opkg("remove", "--force-remove", "mudi-volte", MODE="none")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("removed anyway", r.stderr)
        self.assertIn("External VoLTE", r.stderr)
        self.assertKept()  # modem.orig is what gives the modem back later
        self.assertIn("init stop", self.events())
        self.assertFalse((self.sb / "installed").exists())

    def test_reinstall_by_install_sh_keeps_the_modem_and_the_data(self):
        sb = self.sb
        ipk = self.ipk(VERSION)
        script = (ROOT / "package/install.sh.in").read_text()
        script = swap(script, "/proc/device-tree/model", str(sb / "model"))
        script = script.replace("@VERSION@", VERSION).replace("@BASE_URL@", "http://example.invalid")
        script = swap(script, "@SHA256@", hashlib.sha256(ipk.read_bytes()).hexdigest())
        (sb / "install.sh").write_text(script)
        (sb / "model").write_text("GL.iNet GL-E5800\0")
        self.executable("bin/id", "echo 0\n")
        self.executable("bin/uci", 'echo "uci $*" >>"$SB/events"\n')
        r = self.run_sh(SHELL + [str(sb / "install.sh"), str(ipk)], path=str(sb / "bin"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        ev = self.events()
        self.assertIn("opkg install --force-reinstall %s" % ipk, ev)
        self.assertIn("reinstall mark", ev)  # also without opkg's command line to go by
        self.assertIn("init stop", ev)  # prerm and postrm ran as for a removal
        self.assertIn("fw4 -q reload", ev)
        self.assertIn("postinst configure PKG_UPGRADE=0", ev)
        self.assertKept()
        self.assertEqual(self.read("installed").strip(), VERSION + "-1")

    def test_reinstall_by_hand_keeps_the_modem_and_the_data(self):
        r = self.opkg("install", "--force-reinstall", str(self.ipk(VERSION)))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("fw4 -q reload", self.events())  # postrm remove ran
        self.assertKept()

    def test_reinstall_mark_alone_keeps_the_modem_and_the_data(self):
        # install.sh's mark, without opkg on the command line of a parent.
        for name in ("prerm", "postrm"):
            r = self.run_sh([str(self.sb / "info" / name), "remove"], MUDI_VOLTE_REINSTALL="1")
            self.assertEqual(r.returncode, 0, r.stderr)
        self.assertKept()

    def test_upgrade_and_downgrade_keep_the_modem_and_the_data(self):
        for flags, version in (((), "99.0.0"), (("--force-downgrade",), "0.0.1")):
            with self.subTest(version=version):
                r = self.opkg("install", *flags, str(self.ipk(version)))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("postinst configure PKG_UPGRADE=1", self.events())
                self.assertKept()

    def test_uninstall_gives_the_modem_back_once(self):
        r = self.run_sh([str(self.sb / "cli"), "uninstall", "-y"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read("at").splitlines(), GIVE_BACK)  # not a second time from prerm
        ev = self.events()
        self.assertEqual(ev.count("ask"), 1, ev)
        self.assertEqual(ev.count("sleep restored"), 1, ev)
        self.assertIn("opkg remove mudi-volte", ev)
        self.assertIn("fw4 -q reload", ev)  # postrm ran
        self.assertEqual(ev[-1], "reboot")
        self.assertFalse((self.sb / "installed").exists())
        self.assertFalse((self.sb / "data").exists())
        self.assertFalse((self.sb / "config").exists())

    def test_uninstall_keep_config_keeps_the_settings(self):
        r = self.run_sh([str(self.sb / "cli"), "uninstall", "-y", "--keep-config"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read("at").splitlines(), GIVE_BACK)
        self.assertEqual(self.events().count("ask"), 1)
        self.assertTrue((self.sb / "config").exists())
        self.assertFalse((self.sb / "data").exists())
        self.assertFalse((self.sb / "installed").exists())

    def test_failed_restore_keeps_the_line(self):
        # 'mudi-volte modem builtin' (and the web pages' "Restore and restart").
        r = self.run_sh([str(self.sb / "cli"), "modem", "builtin", "-y"], FAIL_AT="ue_usage_setting")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.read("at").splitlines(),
                         WRITES + ['AT+QNWPREFCFG="voice_domain",1', 'AT+QCALLCFG="voice_disable",3',
                                   'AT+QCFG="ims",2'])  # set back, and nothing committed
        ev = self.events()
        self.assertFalse([e for e in ev if e.startswith("init ")], ev)
        self.assertNotIn("uci -q set mudi-volte.main.enabled=0", ev)
        self.assertNotIn("reboot", ev)


# GL's power saving (uci lpm) in files, one per value, for the real
# power_saving_off and power_saving_restore; the values of a new router.
LPM_UCI = r'''
uci() {
 echo "uci $*" >>"$SB/events"
 [ "$1" = -q ] && shift
 case "$1" in
 get)
  case "$2" in
  lpm.global.*) cat "$SB/lpm/${2#lpm.global.}" 2>/dev/null ;;
  mudi-volte.main.country) echo 44 ;;
  esac ;;
 set)
  case "$2" in
  lpm.global.*=*) k=${2#lpm.global.}; echo "${k#*=}" >"$SB/lpm/${k%%=*}" ;;
  esac ;;
 esac
 return 0
}
'''
LPM = {"system_sleep_enable": "1", "wifi_sleep_time": "900",
       "phy_sleep_time": "900", "auto_shutdown_time": "18000"}

# setup's writes on a modem with its own voice (the stubs' defaults: ims 1,
# voice_disable 2, ue_usage 0, voice_domain 3), and those values, which a
# failed setup writes back.
SETUP = ['AT+QCFG="ims",2', 'AT+QCALLCFG="voice_disable",3',
         'AT+QNWPREFCFG="ue_usage_setting",1', 'AT+QNWPREFCFG="voice_domain",1']
BEFORE = ['AT+QCFG="ims",1', 'AT+QCALLCFG="voice_disable",2',
          'AT+QNWPREFCFG="ue_usage_setting",0', 'AT+QNWPREFCFG="voice_domain",3']
OWN_VOICE = {"MODE": "1", "VD": "2", "VDOM": "3", "UE": "0"}


class FailedSetup(unittest.TestCase):
    """setup when the modem does not take one of its values: the values
    written so far go back, setup fails, and the service, the restart and the
    router's sleep settings are left alone. The real cmd_setup,
    power_saving_off and power_saving_restore; uci keeps GL's power saving
    values in files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mudi-setup-")
        self.addCleanup(self.tmp.cleanup)
        self.sb = sb = Path(self.tmp.name)
        (sb / "lpm").mkdir()
        for k, v in LPM.items():
            (sb / "lpm" / k).write_text(v + "\n")
        src = SOURCE.replace("/etc/init.d/gl_screen", "screen_stub")
        src = swap(src, "/etc/init.d/lpm_monitor", str(sb / "lpm_monitor"))
        src = src.replace("/etc/config/mudi-volte", str(sb / "config"))
        stubs = swap(STUBS, "power_saving_off() { :; }\npower_saving_restore() { :; }\n", "")
        # FAIL_UNDO: a second value the modem refuses, for a failed undo.
        stubs = swap(stubs, ' case "$1" in *"${FAIL_AT:-not-a-command}"*) return 1 ;; esac\n',
                     ' case "$1" in *"${FAIL_AT:-not-a-command}"* | *"${FAIL_UNDO:-not-a-command}"*) return 1 ;; esac\n')
        stubs = swap(stubs, 'uci() {\n echo "uci $*" >>"$SB/events"\n case "$*" in\n'
                     ' *get*mudi-volte.main.country*) echo 44 ;;\n esac\n}\n', LPM_UCI)
        self.base = src + "\n" + stubs

    def setup(self, *args, **env):
        p = self.sb / "case.sh"
        p.write_text(self.base + "\ncmd_setup " + " ".join(args) + "\n")
        return subprocess.run(SHELL + [str(p)], env={**os.environ, "SB": str(self.sb), **env},
                              text=True, capture_output=True, timeout=10)

    def read(self, name):
        p = self.sb / name
        return p.read_text() if p.exists() else ""

    def lpm(self):
        return {k: self.read("lpm/" + k).strip() for k in LPM}

    def assertLeftAlone(self, r):
        """An error, no restart, the service and the sleep settings untouched."""
        ev = self.read("events")
        self.assertFalse(r.returncode == 0 or "reboot" in ev or "mudi-volte.main.enabled" in ev or "init " in ev,
                         "setup went on (code %d): %r; stderr %r" % (r.returncode, ev, r.stderr))
        self.assertEqual(self.lpm(), LPM, "a failed setup changed the router's sleep settings")
        self.assertFalse((self.sb / "data/lpm.orig").exists())
        self.assertIn("setup stopped", r.stderr)

    def test_refused_voice_setting_fails_the_setup(self):
        # Review 14.11: setup only warned, enabled the service, restarted the
        # router and succeeded; without voice_domain 1 the network may move a
        # call to 3G, where the modem has no voice.
        for i, failed in enumerate(("voice_disable", "ue_usage_setting", "voice_domain")):
            with self.subTest(failed=failed):
                for name in ("at", "events", "data/modem.orig"):
                    (self.sb / name).unlink(missing_ok=True)
                r = self.setup(FAIL_AT=failed)
                self.assertLeftAlone(r)
                self.assertIn("the modem refused " + SETUP[i + 1], r.stderr)
                # Written, refused, then the values from before, newest first.
                self.assertEqual(self.read("at").splitlines(), SETUP[:i + 2] + BEFORE[:i + 1][::-1])
                self.assertFalse((self.sb / "data/modem.orig").exists())  # saved by this run

    def test_refused_lte_lock_fails_the_setup(self):
        r = self.setup("--lte-only", FAIL_AT="mode_pref")
        self.assertLeftAlone(r)
        self.assertEqual(self.read("at").splitlines(),
                         SETUP + ['AT+QNWPREFCFG="mode_pref",LTE:NR5G'] + BEFORE[::-1])

    def test_refused_mode_switch_keeps_sleep_settings(self):
        # Review 14.11 (docs): "a failed setup leaves the router as it was",
        # but sleep and auto power-off were off already, on a router that
        # runs on its battery.
        r = self.setup(FAIL_AT='QCFG="ims",2')
        self.assertLeftAlone(r)
        self.assertIn('refused AT+QCFG="ims",2', r.stderr)
        self.assertEqual(self.read("at").splitlines(), SETUP[:1])

    def test_unanswering_modem_changes_nothing(self):
        r = self.setup(MODE="none")
        self.assertLeftAlone(r)
        self.assertIn("does not answer", r.stderr)
        self.assertEqual(self.read("at"), "")
        self.assertFalse((self.sb / "data/modem.orig").exists())

    def test_failed_undo_keeps_the_saved_values(self):
        r = self.setup(FAIL_AT="voice_domain", FAIL_UNDO='ue_usage_setting",0')
        self.assertLeftAlone(r)
        self.assertIn("nor all the values from before back", r.stderr)
        self.assertIn("mudi-volte modem builtin", r.stderr)
        self.assertEqual(self.read("at").splitlines(), SETUP + BEFORE[:3][::-1])
        self.assertTrue((self.sb / "data/modem.orig").exists())  # what modem builtin restores

    def test_values_saved_by_an_earlier_setup_stay(self):
        (self.sb / "data").mkdir()
        saved = "ims=0\nvoice_disable=3\nmode_pref=AUTO\nvoice_domain=3\nue_usage=0\n"
        (self.sb / "data/modem.orig").write_text(saved)
        r = self.setup(FAIL_AT="voice_domain")
        self.assertLeftAlone(r)
        self.assertEqual(self.read("data/modem.orig"), saved)

    def test_modem_already_external_stays_as_it_was(self):
        # Switched by hand, or set up before: setup adds the voice settings,
        # and a refusal neither enables nor restarts the service.
        r = self.setup(MODE="2", VDOM="3", UE="0", FAIL_AT="voice_domain")
        self.assertLeftAlone(r)
        self.assertEqual(self.read("at").splitlines(), SETUP[2:] + BEFORE[2:3])
        self.assertFalse((self.sb / "data/modem.orig").exists())

    def test_sleep_goes_off_once_the_modem_took_every_value(self):
        r = self.setup()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read("at").splitlines(), SETUP)
        self.assertEqual(self.lpm(), dict.fromkeys(LPM, "0"))
        self.assertEqual(self.read("data/lpm.orig").splitlines(), ["%s=%s" % kv for kv in LPM.items()])
        ev = self.read("events")
        self.assertIn("enabled=1", ev)
        self.assertIn("init enable", ev)
        self.assertTrue(ev.endswith("reboot\n"), ev)


class WebPageRuns(unittest.TestCase):
    """Setup and "Restore and restart" on the web pages: 'setup --detach' and
    'modem builtin --detach' go on in the background, and the pages read how
    the run goes from its log and its state file. The real CLI as an
    executable, as in RawPackageRemoval; the restart records the state the
    pages see at that moment."""

    executable = RawPackageRemoval.executable
    run_sh = RawPackageRemoval.run_sh
    read = RawPackageRemoval.read
    events = RawPackageRemoval.events

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mudi-web-")
        self.addCleanup(self.tmp.cleanup)
        self.sb = sb = Path(self.tmp.name)
        (sb / "data").mkdir()
        (sb / "config").write_text("config voip 'main'\n")
        cli = swap(RawPackageRemoval.cli(self), 'modem_reboot() { echo reboot >>"$SB/events"; }',
                   'modem_reboot() { echo "reboot, state $(cat "$SETUP_STATE")" >>"$SB/events"; }')
        self.executable("cli", cli)

    def saved(self):
        (self.sb / "data/modem.orig").write_text(
            "ims=1\nvoice_disable=2\nmode_pref=AUTO\nvoice_domain=3\nue_usage=0\n")

    def background(self, *args, **env):
        """Start a run as the pages do; wait for its end, return its code."""
        r = self.run_sh([str(self.sb / "cli"), *args], **env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Started in the background", r.stdout)
        for _ in range(200):
            state = self.read("setup.state").strip()
            if state.startswith("exit "):
                return int(state.split()[1])
            time.sleep(0.05)
        self.fail("the background run did not end: %r" % self.read("setup.state"))

    def assertNoRestart(self):
        ev = self.events()
        self.assertFalse([e for e in ev if e.startswith(("init ", "reboot"))], ev)

    def test_refused_restore_tells_the_pages_why(self):
        # Review 14.11: "Restore and restart" announced a restart and showed
        # no error, although the modem refused and the router kept running.
        self.saved()
        code = self.background("modem", "builtin", "--detach", FAIL_AT="ue_usage_setting")
        self.assertNotEqual(code, 0)
        self.assertIn("mudi-volte: the modem's own VoLTE is not restored", self.read("setup.log"))
        self.assertNoRestart()  # the phone line keeps working
        self.assertNotIn("uci -q set mudi-volte.main.enabled=0", self.events())

    def test_restore_tells_the_pages_before_the_restart(self):
        self.saved()
        self.assertEqual(self.background("modem", "builtin", "--detach"), 0)  # the restart is a stub
        self.assertEqual(self.read("at").splitlines(), GIVE_BACK)
        ev = self.events()
        self.assertIn("init disable", ev)
        self.assertEqual(ev[-1], "reboot, state restarting")

    def test_refused_setup_tells_the_pages_why(self):
        code = self.background("setup", "--detach", FAIL_AT="voice_domain", **OWN_VOICE)
        self.assertNotEqual(code, 0)
        log = self.read("setup.log")
        self.assertIn('mudi-volte: the modem refused AT+QNWPREFCFG="voice_domain",1', log)
        self.assertIn("mudi-volte: setup stopped", log)
        self.assertNoRestart()
        self.assertFalse([e for e in self.events() if "enabled=1" in e])

    def test_setup_tells_the_pages_before_the_restart(self):
        self.assertEqual(self.background("setup", "--detach", **OWN_VOICE), 0)
        self.assertEqual(self.read("at").splitlines(), SETUP)
        self.assertEqual(self.events()[-1], "reboot, state restarting")

    def test_any_end_reaches_the_pages(self):
        code = self.background("setup", "--detach", "--no-such-option", **OWN_VOICE)
        self.assertEqual(code, 1)
        self.assertIn("unknown option --no-such-option", self.read("setup.log"))

    def test_one_run_at_a_time(self):
        (self.sb / "setup.state").write_text("running %d\n" % os.getpid())
        r = self.run_sh([str(self.sb / "cli"), "setup", "--detach"], **OWN_VOICE)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("running already", r.stderr)
        self.assertEqual(self.read("at"), "")
        # A wrapper that was killed: its process is gone, a new run may start.
        gone = subprocess.Popen(["true"])
        gone.wait()
        (self.sb / "setup.state").write_text("running %d\n" % gone.pid)
        self.assertEqual(self.background("setup", "--detach", **OWN_VOICE), 0)


if __name__ == "__main__":
    unittest.main()
