#!/usr/bin/env python3
"""Drive mudi-dsi-helper against a stand-in for the firmware's DSI library.

No router needed. The helper and dsi_stub.c are built with the host compiler,
and the helper runs the way mudi-imsd runs it: a pipe for its events, a pipe
held open as its stdin, a signal to stop it.

  DSI_HELPER_CC      the compiler (default: cc)
  DSI_HELPER_CFLAGS  more flags, e.g. "-fsanitize=address,undefined"
  DSI_HELPER_RUN     what to run the helper under, e.g. the loader of the
                     libc it was built for
"""
import json
import os
from pathlib import Path
import queue
import select
import shlex
import signal
import subprocess
import tempfile
import threading
import time
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "mudi-dsi-helper.c"
STUB = HERE / "dsi_stub.c"
CC = shlex.split(os.environ.get("DSI_HELPER_CC", "cc"))
CFLAGS = ["-O2", "-Wall", "-Wextra", "-Werror"] + shlex.split(os.environ.get("DSI_HELPER_CFLAGS", ""))
RUN = shlex.split(os.environ.get("DSI_HELPER_RUN", ""))

# Leave time for the stub's NO_NET thread even on a busy host. A confirmed
# stop returns as soon as the event arrives, not when STOP_MS expires.
RETRY_MS, HANDLE_MS, STOP_MS = 20, 2000, 2000
# Only the missing-confirmation test needs to wait out the whole deadline.
SILENT_STOP_MS = 400
# How long "check" waits for the library, in seconds.
CHECK_S = 2

# What the stub sees before the call starts, for "1 2 ipv4v6".
SETUP = ["subs 1", "init 0", "handle", "param 11 num=10 buf=null", "param 1 num=2 buf=null"]

TMP = None      # a directory for everything built and logged
HELPER = None   # the helper, built for the stub
SILENT_STOP_HELPER = None  # a short deadline for the missing-confirmation test


def compile_c(out, source, *flags):
    subprocess.run(CC + CFLAGS + list(flags) + ["-o", str(out), str(source), "-ldl"], check=True)


def build_helper(name, library, stop_ms=STOP_MS):
    """A helper for this library file."""
    out = Path(TMP.name) / name
    compile_c(out, SOURCE, "-pthread",
              '-DMUDI_DSI_LIBRARY="%s"' % library,
              "-DHANDLE_RETRY_MS=%d" % RETRY_MS, "-DHANDLE_TIMEOUT_MS=%d" % HANDLE_MS,
              "-DSTOP_WAIT_MS=%d" % stop_ms, "-DCHECK_TIMEOUT_S=%d" % CHECK_S)
    return out


def setUpModule():
    global TMP, HELPER, SILENT_STOP_HELPER
    TMP = tempfile.TemporaryDirectory(prefix="mudi-dsi-helper-")
    unittest.addModuleCleanup(TMP.cleanup)
    stub = Path(TMP.name) / "libdsi_stub.so"
    compile_c(stub, STUB, "-shared", "-fPIC", "-pthread")
    HELPER = build_helper("helper", stub)
    SILENT_STOP_HELPER = build_helper("helper-silent-stop", stub, SILENT_STOP_MS)


class Run:
    """One helper process and what it says."""

    count = 0

    def __init__(self, test, binary, args, mode="", stdin="pipe"):
        Run.count += 1
        self.test = test
        self.log = Path(TMP.name) / ("calls-%d.log" % Run.count)
        command = RUN + [str(binary)] + list(args)
        if stdin == "none":
            command = ["/bin/sh", "-c", 'exec "$@" <&-', "sh"] + command
        read_end, write_end = os.pipe()
        err_read, err_write = os.pipe()
        self.proc = subprocess.Popen(
            command, stdout=write_end, stderr=err_write,
            stdin={"pipe": subprocess.PIPE, "null": subprocess.DEVNULL, "none": None}[stdin],
            env={**os.environ, "DSI_STUB_LOG": str(self.log), "DSI_STUB_MODE": mode})
        os.close(write_end)
        os.close(err_write)
        self.lines = queue.Queue()
        self.deaf = threading.Event()
        self.blind = threading.Event()
        self.complaints = []
        self.readers = [threading.Thread(target=self._events, args=(read_end,), daemon=True),
                        threading.Thread(target=self._stderr, args=(err_read,), daemon=True)]
        for reader in self.readers:
            reader.start()
        test.addCleanup(self._cleanup)

    def _events(self, fd):
        rest = b""
        while not self.deaf.is_set():
            if not select.select([fd], [], [], 0.02)[0]:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            *whole, rest = (rest + chunk).split(b"\n")
            for line in whole:
                self.lines.put(line)
        os.close(fd)
        self.lines.put(None)

    def _stderr(self, fd):
        while not self.blind.is_set():
            if not select.select([fd], [], [], 0.02)[0]:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            self.complaints.append(chunk.decode(errors="replace"))
        os.close(fd)

    def _cleanup(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        self.deaf.set()
        self.blind.set()
        for reader in self.readers:
            reader.join(timeout=5)
        if self.proc.stdin is not None:
            self.proc.stdin.close()

    def stderr(self):
        return "".join(self.complaints)

    def calls(self, everything=False):
        """The stub's log: its calls and events, without the thread report."""
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return [line for line in lines if everything or not line.startswith("thread ")]

    def event(self, timeout=5.0):
        """The next event; None when the helper has closed its stdout."""
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            self.test.fail("no event in %.1f s; stderr: %s" % (timeout, self.stderr()))
        if line is None:
            return None
        try:
            event = json.loads(line)
        except ValueError:
            self.test.fail("not an event: %r" % line)
        self.test.assertIsInstance(event, dict, line)
        self.test.assertEqual(event.get("v"), 1, line)
        return event

    def expect(self, name, **fields):
        event = self.event()
        self.test.assertIsNotNone(event, "ended before %r; stderr: %s" % (name, self.stderr()))
        self.test.assertEqual(event.get("event"), name, event)
        for key, value in fields.items():
            self.test.assertEqual(event.get(key), value, event)
        return event

    def quiet(self, seconds):
        """Nothing is said for this long."""
        try:
            line = self.lines.get(timeout=seconds)
        except queue.Empty:
            return
        self.test.fail("unexpected: %r" % line)

    def stop(self, sig=signal.SIGTERM):
        self.proc.send_signal(sig)

    def stopped(self, sig=signal.SIGTERM):
        """The helper says who stopped it (0: the end of its stdin), then the call ends."""
        self.expect("stopping", signal=int(sig))
        self.expect("net_down")

    def hang_up(self):
        """Stop reading the events, as a daemon that died would."""
        self.deaf.set()
        self.readers[0].join(timeout=5)

    def die(self):
        """Go the way a daemon killed outright goes: nobody reads the events or
        stderr any more, and stdin is at its end."""
        self.deaf.set()
        self.blind.set()
        for reader in self.readers:
            reader.join(timeout=5)
        self.proc.stdin.close()

    def end(self, code):
        """The helper says it leaves with this status, and does."""
        self.expect("exiting", code=code)
        self.test.assertIsNone(self.event())
        self.exited(code)

    def exited(self, code):
        self.test.assertEqual(self.proc.wait(timeout=10), code, self.stderr())
        self.readers[1].join(timeout=5)
        for sign in ("Sanitizer", "runtime error"):
            self.test.assertNotIn(sign, self.stderr())
        # The library's exit handler takes its state apart under its threads.
        self.test.assertNotIn("exit handler", self.calls())


class Helper(unittest.TestCase):
    maxDiff = None

    def start(self, *args, mode="", binary=None, stdin="pipe"):
        return Run(self, binary or HELPER, args, mode, stdin)

    def call(self, *args, mode="", stdin="pipe", binary=None):
        """A helper for a call, past the loading of its library."""
        run = self.start(*args, mode=mode, stdin=stdin, binary=binary)
        run.expect("library")
        return run

    def up(self, mode="", binary=None):
        """A call that is up."""
        run = self.call("1", "2", "ipv4v6", mode=mode, binary=binary)
        run.expect("ready")
        run.expect("net_up")
        return run

    # The call the daemon asks for.

    def test_up_and_stopped_by_sigterm(self):
        run = self.call("1", "2", "ipv4v6")
        ready = run.expect("ready", subscription=1, profile=2, family="ipv4v6", tries=1)
        self.assertEqual(ready["pid"], run.proc.pid)
        run.expect("net_up")
        run.quiet(0.2)
        run.stop()
        run.stopped()
        run.end(0)
        self.assertEqual(run.calls(), SETUP + ["start", "event 1", "stop", "event 2", "release"])

    def test_stopped_by_other_signals(self):
        for sig in (signal.SIGINT, signal.SIGHUP):
            with self.subTest(sig=sig):
                run = self.up()
                run.stop(sig)
                run.stopped(sig)
                run.end(0)
                self.assertEqual(run.calls()[-3:], ["stop", "event 2", "release"])

    def test_stopped_by_the_end_of_stdin(self):
        run = self.up()
        run.proc.stdin.write(b"input means nothing\n")
        run.proc.stdin.flush()
        run.quiet(0.2)
        run.proc.stdin.close()
        run.stopped(0)
        run.end(0)
        self.assertEqual(run.calls(), SETUP + ["start", "event 1", "stop", "event 2", "release"])
        self.assertIn("stdin is closed", run.stderr())

    def test_ipv4_and_another_profile(self):
        run = self.call("1", "5", "ipv4")
        run.expect("ready", subscription=1, profile=5, family="ipv4")
        run.expect("net_up")
        run.stop()
        run.stopped()
        run.end(0)
        self.assertEqual(run.calls()[3:5], ["param 11 num=4 buf=null", "param 1 num=5 buf=null"])

    def test_the_technology_is_left_to_the_modem(self):
        # "AUTOMATIC" in the menu of the firmware's tool sets technology 0, which the library
        # refuses; the tool never notices. Nothing may set that parameter here.
        run = self.up()
        run.stop()
        run.stopped()
        run.end(0)
        self.assertEqual([call for call in run.calls() if call.startswith("param 9 ")], [])
        self.assertEqual([call for call in run.calls() if call.endswith(" refused")], [])

    def test_the_largest_profile(self):
        run = self.call("1", "255", "ipv4v6")
        run.expect("ready", profile=255)
        run.expect("net_up")
        run.stop()
        run.stopped()
        run.end(0)
        self.assertEqual(run.calls()[4], "param 1 num=255 buf=null")

    def test_subscription(self):
        for subscription, first in (("0", "init 0"), ("2", "subs 2")):
            with self.subTest(subscription=subscription):
                run = self.call(subscription, "2", "ipv4v6")
                run.expect("ready", subscription=int(subscription))
                run.expect("net_up")
                run.stop()
                run.stopped()
                run.end(0)
                self.assertEqual(run.calls()[0], first)
                self.assertEqual(run.calls().count("init 0"), 1)

    def test_library_threads_leave_the_stop_signals_alone(self):
        run = self.up()
        run.stop()
        run.stopped()
        run.end(0)
        self.assertIn("thread term=1 int=1 hup=1 pipe=0", run.calls(everything=True))

    # What the network may do.

    def test_refused(self):
        run = self.call("1", "2", "ipv4v6", mode="refuse")
        run.expect("ready")
        run.expect("net_down")
        run.end(3)
        self.assertEqual(run.calls(), SETUP + ["start", "event 2", "release"])

    def test_refused_for_one_ip_version(self):
        # What the daemon does next is ask for IPv4 alone.
        run = self.call("1", "2", "ipv4v6", mode="refuse_ip=10")
        run.expect("ready")
        run.expect("net_down")
        run.end(3)
        run = self.call("1", "2", "ipv4", mode="refuse_ip=10")
        run.expect("ready", family="ipv4")
        run.expect("net_up")
        run.stop()
        run.stopped()
        run.end(0)

    def test_dropped_by_the_network(self):
        run = self.up("drop")
        run.expect("net_down")
        run.end(3)
        self.assertEqual(run.calls(), SETUP + ["start", "event 1", "event 2", "release"])

    def test_no_reply_then_stopped(self):
        run = self.call("1", "2", "ipv4v6", mode="silent")
        run.expect("ready")
        run.quiet(0.3)
        run.stop()
        run.stopped()
        run.end(0)
        self.assertEqual(run.calls(), SETUP + ["start", "stop", "event 2", "release"])

    def test_other_events_are_passed_on_by_number(self):
        run = self.call("1", "2", "ipv4v6", mode="extra")
        run.expect("ready")
        run.expect("dsi_event", code=4)
        run.expect("net_up")
        run.expect("dsi_event", code=8)
        run.expect("dsi_event", code=5)
        run.stop()
        run.stopped()
        run.end(0)

    def test_events_of_another_call_are_ignored(self):
        run = self.call("1", "2", "ipv4v6", mode="stranger,refuse")
        run.expect("ready")
        run.expect("net_down")
        run.end(3)
        self.assertIn("event 1 for a stranger", run.calls())

    # A library that is not ready, or fails.

    def test_asks_for_the_handle_until_the_library_has_one(self):
        run = self.call("1", "2", "ipv4v6", mode="not_ready=3")
        run.expect("ready", tries=4)
        run.expect("net_up")
        run.stop()
        run.stopped()
        run.end(0)
        self.assertEqual(run.calls()[2:6], ["handle refused"] * 3 + ["handle"])

    def test_gives_up_on_a_library_that_never_has_a_handle(self):
        started = time.monotonic()
        run = self.call("1", "2", "ipv4v6", mode="never_ready")
        run.expect("error", stage="dsi_get_data_srvc_hndl", code=0)
        run.end(1)
        self.assertGreaterEqual(time.monotonic() - started, HANDLE_MS / 1000)
        calls = run.calls()
        self.assertEqual(calls[:2], ["subs 1", "init 0"])
        self.assertGreater(len(calls), 10)
        self.assertEqual(set(calls[2:]), {"handle refused"})

    def test_stopped_while_waiting_for_the_handle(self):
        for how in ("signal", "stdin"):
            with self.subTest(how=how):
                started = time.monotonic()
                run = self.call("1", "2", "ipv4v6", mode="never_ready")
                while "handle refused" not in run.calls():
                    self.assertLess(time.monotonic() - started, 1.5)
                    time.sleep(0.01)
                if how == "signal":
                    run.stop()
                else:
                    run.proc.stdin.close()
                run.end(0)
                self.assertEqual(set(run.calls()[2:]), {"handle refused"})

    def test_failures_before_the_call(self):
        cases = (
            ("fail_subs", {"stage": "dsi_set_modem_subs_id", "code": -1}, ["subs 1"]),
            ("fail_init", {"stage": "dsi_init", "code": -1}, ["subs 1", "init 0"]),
            ("fail_param=11", {"stage": "dsi_set_data_call_param", "code": -1, "param": 11},
             SETUP[:3] + ["param 11 num=10 buf=null refused", "release"]),
            ("fail_param=1", {"stage": "dsi_set_data_call_param", "code": -1, "param": 1},
             SETUP[:4] + ["param 1 num=2 buf=null refused", "release"]),
            ("fail_start", {"stage": "dsi_start_data_call", "code": -1}, SETUP + ["start", "release"]),
        )
        for mode, error, calls in cases:
            with self.subTest(mode=mode):
                run = self.call("1", "2", "ipv4v6", mode=mode)
                if mode == "fail_start":
                    run.expect("ready")
                run.expect("error", **error)
                run.end(1)
                self.assertEqual(run.calls(), calls)

    def test_stop_that_fails_still_releases(self):
        run = self.up("fail_stop")
        run.stop()
        run.expect("stopping", signal=signal.SIGTERM)
        run.expect("error", stage="dsi_stop_data_call", code=-1)
        run.end(0)
        self.assertEqual(run.calls()[-2:], ["stop", "release of a call that is up"])

    def test_stop_without_confirmation_releases_after_a_wait(self):
        run = self.up("silent_stop", binary=SILENT_STOP_HELPER)
        stopped = time.monotonic()
        run.stop()
        time.sleep(0.1)
        run.stop()  # an impatient second request changes nothing
        run.expect("stopping", signal=signal.SIGTERM)
        run.end(0)
        self.assertGreaterEqual(time.monotonic() - stopped, SILENT_STOP_MS / 1000)
        self.assertEqual(run.calls()[-2:], ["stop", "release of a call that is up"])
        self.assertIn("no NO_NET", run.stderr())

    def test_delayed_stop_confirmation_is_not_lost(self):
        # A delayed stub thread must not turn a confirmed stop into a timeout.
        # Keep this beyond the old 400 ms test deadline, but within STOP_MS.
        for how in ("signal", "stdin"):
            with self.subTest(how=how):
                run = self.up("slow_stop=750")
                if how == "signal":
                    run.stop()
                else:
                    run.proc.stdin.close()
                run.stopped(signal.SIGTERM if how == "signal" else 0)
                run.end(0)
                self.assertEqual(run.calls(), SETUP + ["start", "event 1", "stop", "event 2", "release"])
                self.assertNotIn("no NO_NET", run.stderr())

    # The channels.

    def test_what_the_library_prints_stays_out_of_the_events(self):
        run = self.up("noise")
        run.stop()
        run.stopped()
        run.end(0)
        for where in ("on stdout, buffered", "on stdout, written", "on stderr"):
            for what in ("loading", "dsi_init", "an event"):
                self.assertIn("dsi_stub: %s %s" % (what, where), run.stderr())

    def test_a_reader_that_went_away_stops_the_call(self):
        run = self.up("chatter")
        run.expect("dsi_event", code=8)
        run.hang_up()
        run.exited(0)
        calls = [call for call in run.calls() if call != "event 8"]
        self.assertEqual(calls[-3:], ["stop", "event 2", "release"])
        self.assertIn("event channel is closed", run.stderr())

    def test_a_reader_that_went_away_before_the_call_gets_none(self):
        # The library has no handle for half a second: the reader is gone by "ready".
        run = self.call("1", "2", "ipv4v6", mode="not_ready=25")
        run.hang_up()
        run.exited(0)
        self.assertEqual(run.calls(), SETUP[:2] + ["handle refused"] * 25 + SETUP[2:] + ["release"])
        self.assertIn("event channel is closed", run.stderr())

    def test_a_reader_that_went_away_does_not_kill_on_net_down(self):
        run = self.up("drop")
        run.hang_up()
        run.exited(3)
        self.assertEqual(run.calls()[-2:], ["event 2", "release"])

    def test_a_daemon_that_died_stops_the_call(self):
        # A daemon killed outright leaves the end of stdin and nobody behind the events
        # and stderr. A line written to either must not end the helper before it has
        # stopped the call, whether the helper writes it or a thread of the library.
        for mode in ("", "noise"):
            with self.subTest(mode=mode):
                run = self.up(mode)
                run.die()
                run.exited(0)
                self.assertEqual(run.calls()[-3:], ["stop", "event 2", "release"])

    def test_started_without_a_stdin(self):
        run = self.call("1", "2", "ipv4v6", stdin="none")
        run.expect("ready")
        run.expect("net_up")
        run.quiet(0.3)
        run.stop()
        run.stopped()
        run.end(0)

    def test_stdin_at_its_end_from_the_start_means_no_call(self):
        run = self.call("1", "2", "ipv4v6", stdin="null")
        run.end(0)
        self.assertEqual(run.calls(), SETUP + ["release"])

    # The command line.

    def test_usage(self):
        for args in ([], ["1"], ["1", "2"], ["1", "2", "ipv4", "more"], ["3", "2", "ipv4"],
                     ["-1", "2", "ipv4"], ["x", "2", "ipv4"], ["", "2", "ipv4"], ["1", "0", "ipv4"],
                     ["1", "256", "ipv4"], ["1", "1001", "ipv4"], ["1", "+2", "ipv4"], ["1", " 2", "ipv4"],
                     ["1", "2x", "ipv4"], ["1", "2", "ipv6"], ["1", "2", "10"], ["1", "2", "IPV4"],
                     ["1", "2", ""], ["check", "2", "ipv4"], ["check", "more"], ["help"]):
            with self.subTest(args=args):
                run = self.start(*args)
                self.assertIsNone(run.event())
                run.exited(2)
                self.assertIn("usage: mudi-dsi-helper", run.stderr())
                self.assertEqual(run.calls(), [])

    # The library file.

    def test_check_finds_the_library(self):
        run = self.start("check")
        run.expect("library")
        run.end(0)
        self.assertEqual(run.calls(), [], "check must not call into the library")

    def test_check_keeps_what_the_library_prints_out_of_the_events(self):
        run = self.start("check", mode="noise")
        run.expect("library")
        run.end(0)
        for where in ("on stdout, buffered", "on stdout, written", "on stderr"):
            self.assertIn("dsi_stub: loading " + where, run.stderr())

    def test_check_has_no_call_to_stop_and_ends_at_a_signal(self):
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(sig=sig):
                if signal.getsignal(sig) == signal.SIG_IGN:
                    # Under nohup, say. The helper is started with it ignored too.
                    self.skipTest("%s is ignored where the tests run" % sig.name)
                run = self.start("check", mode="slow_load=30000")
                deadline = time.monotonic() + 5
                while run.calls() != ["loading"] and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(run.calls(), ["loading"])
                run.stop(sig)
                self.assertEqual(run.proc.wait(timeout=5), -sig)
                self.assertIsNone(run.event())

    def test_check_gives_up_on_a_library_that_does_not_load(self):
        started = time.monotonic()
        run = self.start("check", mode="slow_load=30000")
        run.expect("error", stage="library_load", code=0)
        run.end(1)
        took = time.monotonic() - started
        self.assertGreaterEqual(took, CHECK_S)
        self.assertLess(took, CHECK_S + 3)
        self.assertEqual(run.calls(), ["loading"])
        self.assertIn("did not load within %d s" % CHECK_S, run.stderr())

    def unusable(self, helper, stage):
        """Neither a call nor check gets anywhere with this library."""
        said = []
        for args in (("1", "2", "ipv4v6"), ("check",)):
            with self.subTest(args=args):
                run = self.start(*args, binary=helper)
                run.expect("error", stage=stage, code=0)
                run.end(1)
                self.assertEqual(run.calls(), [])
                said.append(run.stderr())
        return said

    def test_no_library(self):
        lost = build_helper("helper-lost", Path(TMP.name) / "no-such-library.so")
        for stderr in self.unusable(lost, "library_load"):
            self.assertIn("no-such-library.so", stderr)

    def test_a_file_that_does_not_load(self):
        junk = Path(TMP.name) / "junk.so"
        junk.write_text("not a library\n")
        for stderr in self.unusable(build_helper("helper-junk", junk), "library_load"):
            self.assertIn("junk.so", stderr)

    def test_a_library_without_the_functions(self):
        source = Path(TMP.name) / "partial.c"
        source.write_text("int dsi_init(int mode);\nint dsi_init(int mode) { return mode; }\n")
        partial = Path(TMP.name) / "libpartial.so"
        compile_c(partial, source, "-shared", "-fPIC")
        for stderr in self.unusable(build_helper("helper-partial", partial), "library_symbol"):
            for name in ("dsi_set_modem_subs_id", "dsi_get_data_srvc_hndl", "dsi_set_data_call_param",
                         "dsi_start_data_call", "dsi_stop_data_call", "dsi_rel_data_srvc_hndl"):
                self.assertIn("has no " + name, stderr)
            self.assertNotIn("has no dsi_init", stderr)


if __name__ == "__main__":
    unittest.main()
