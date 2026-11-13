// Test of the LuCI page (www/luci-static/resources/view/mudi-volte/overview.js)
// in node: LuCI's modules are stubs, the page is compiled the way LuCI does it
// (its source as the body of a function with the required modules as
// arguments). It drives the background runs of setup and of the restore the
// way the page polls them.
//   package/tests/run.sh
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const SETUP_LOG = '/tmp/mudi-volte-setup.log';
const SETUP_STATE = '/tmp/mudi-volte-setup.state';

// --- LuCI: E, _, String.format, view, fs, ui, poll, dom, L ---

function E(tag, attrs, children) {
	if (Array.isArray(attrs) || typeof attrs !== 'object') {
		children = attrs;
		attrs = {};
	}
	return { tag: tag, attrs: attrs || {}, children: [].concat(children == null ? [] : children) };
}
function text(n) {
	if (n == null)
		return '';
	if (Array.isArray(n))
		return n.map(text).join('');
	return typeof n === 'object' ? text(n.children) : String(n);
}
const _ = (s) => s;
String.prototype.format = function () { // eslint-disable-line no-extend-native
	const args = Array.from(arguments);
	return this.replace(/%[sd]/g, () => String(args.shift()));
};

let modal = null;
const notes = [];
const ui = {
	showModal(title, children) { modal = { title: title, children: children }; },
	hideModal() { modal = null; },
	addNotification(title, children, cls) { notes.push([cls, text(children)]); }
};
const steps = new Set();
const poll = {
	add(fn, sec) { assert.strictEqual(sec, 3); steps.add(fn); },
	remove(fn) { steps.delete(fn); }
};
const dom = { content(node, children) { node.children = [].concat(children); } };
const files = {};
const execs = [];
let execAnswer = { code: 0, stdout: 'Started in the background; progress: ' + SETUP_LOG };
const luciFs = {
	exec(cmd, args) { execs.push([cmd].concat(args)); return Promise.resolve(execAnswer); },
	read(p) { return p in files ? Promise.resolve(files[p]) : Promise.reject(new Error('no such file')); }
};
const L = { resolveDefault(p, d) { return Promise.resolve(p).catch(() => d); } };
let reloads = 0;
global.location = { reload() { reloads++; } };
global.confirm = () => true;

const source = fs.readFileSync(path.join(__dirname, '../files/www/luci-static/resources/view/mudi-volte/overview.js'), 'utf8');
const page = new Function('view', 'form', 'fs', 'ui', 'uci', 'poll', 'dom', 'E', '_', 'L', source)( // eslint-disable-line no-new-func
	{ extend: (o) => o }, {}, luciFs, ui, {}, poll, dom, E, _, L);

// step runs the page's poll once.
async function step() {
	assert.strictEqual(steps.size, 1, 'one poll of the run');
	await [...steps][0]();
}

function run(state, log) {
	files[SETUP_STATE] = state + '\n';
	files[SETUP_LOG] = log || '';
}

async function main() {
	// "Restore and restart": nothing promises a restart until the modem has
	// taken its values; a refusal shows its reason and stops the poll.
	await page.giveBack();
	assert.deepStrictEqual(execs.pop(), ['/usr/sbin/mudi-volte', 'modem', 'builtin', '--detach']);
	assert.ok(/Giving VoLTE back to the modem/.test(text(modal.children)), 'restore running');
	assert.ok(!/restarts with/.test(text(modal.children)), 'no restart announced at the start');
	await step(); // no state file yet: the run is starting
	run('running 4242');
	await step();
	assert.strictEqual(steps.size, 1);
	const kept = 'the modem\'s own VoLTE is not restored; the service, the package and the settings are kept: retry when the modem answers';
	run('exit 1', 'mudi-volte: could not restore ue_usage_setting 0\nmudi-volte: ' + kept + '\n');
	await step();
	assert.strictEqual(steps.size, 0, 'the poll stops when the run ends');
	const shown = text(modal.children);
	assert.ok(shown.includes('VoLTE is not given back to the modem: ' + kept), 'the reason: ' + shown);
	assert.ok(shown.includes('could not restore ue_usage_setting 0'), 'the log stays');
	assert.ok(!/restarts/.test(shown), 'a failed restore promises no restart');
	assert.strictEqual(modal.children[0].attrs['class'], 'alert-message error');
	assert.strictEqual(reloads, 0);

	// The restore goes through: the restart is announced when it comes.
	await page.giveBack();
	run('restarting', 'Restarting the router...\n');
	await step();
	assert.strictEqual(steps.size, 0);
	assert.ok(/The router restarts with the modem's own VoLTE/.test(text(modal.children)), 'the restart announced');

	// Setup: a refusal of the modem, then a setup that restarts the router,
	// then one on a modem already in External VoLTE mode, which ends without a
	// restart and reloads the page.
	await page.startSetup();
	assert.deepStrictEqual(execs.pop(), ['/usr/sbin/mudi-volte', 'setup', '--detach']);
	assert.ok(/If the router restarts/.test(text(modal.children)), 'setup running');
	const refusal = 'setup stopped: the modem did not take all the settings that calls need';
	run('exit 1', 'mudi-volte: the modem refused AT+QNWPREFCFG="voice_domain",1\nmudi-volte: ' + refusal + '\n');
	await step();
	assert.ok(text(modal.children).includes('Setup failed: ' + refusal), 'the reason of a failed setup');
	assert.ok(!/restarts now/.test(text(modal.children)), 'a failed setup promises no restart');
	await page.startSetup();
	run('restarting', 'Restarting now.\n');
	await step();
	assert.ok(/The router restarts now/.test(text(modal.children)), 'the restart of setup announced');
	await page.startSetup();
	run('exit 0', 'Service: online\n');
	await step();
	assert.strictEqual(modal, null);
	assert.strictEqual(reloads, 1);

	// A run that cannot start (one is running already): its error, no poll.
	execAnswer = { code: 1, stderr: 'mudi-volte: a setup or a restore is running already\n' };
	await page.giveBack();
	assert.strictEqual(steps.size, 0);
	assert.deepStrictEqual(notes.pop(), ['error', 'mudi-volte: a setup or a restore is running already']);

	console.log('luci-view: ok');
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
