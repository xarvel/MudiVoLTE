// Test of the GL admin panel page (www/views/gl-sdk4-ui-mudi-volte.common.js)
// with Vue 2 in node: the panel's components and RPC are stubs, the page is
// evaluated the way the panel does it and rendered to HTML.
//   package/tests/run.sh   (installs vue 2.7 into a temporary directory)
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Vue = require('vue');
const { createRenderer } = require('vue-server-renderer');

Vue.config.productionTip = false;
Vue.config.devtools = false;
const warnings = [];
Vue.config.warnHandler = (msg) => warnings.push(msg);

// --- the panel: global components, $message, $globalLoading, RPC ---

const slot = (h, ctx, name) => (ctx.$slots[name] || []);
Vue.component('gl-title', { props: ['title'], render(h) { return h('h1', this.title); } });
Vue.component('gl-card', {
	props: ['title', 'state'],
	render(h) { return h('section', { attrs: { 'data-state': this.state || '' } }, [h('h2', this.title || ''), slot(h, this, 'default')]); }
});
Vue.component('gl-button', {
	props: ['type', 'disabled'],
	render(h) { return h('button', { attrs: { 'data-type': this.type || '', disabled: this.disabled }, on: { click: () => this.$emit('click') } }, slot(h, this, 'default')); }
});
Vue.component('gl-switch', { props: ['value'], render(h) { return h('input', { attrs: { type: 'checkbox', checked: this.value } }); } });
Vue.component('el-input', { props: ['value', 'placeholder'], render(h) { return h('input', { attrs: { value: this.value, placeholder: this.placeholder } }); } });
Vue.component('el-select', { props: ['value'], render(h) { return h('select', { attrs: { 'data-value': this.value } }, slot(h, this, 'default')); } });
Vue.component('el-option', { props: ['label', 'value'], render(h) { return h('option', { attrs: { value: this.value } }, this.label); } });
Vue.component('el-dialog', {
	props: ['visible', 'title', 'width', 'appendToBody', 'customClass'],
	render(h) { return this.visible ? h('dialog', [h('h3', this.title), slot(h, this, 'default'), h('footer', slot(h, this, 'footer'))]) : h('span'); }
});

const messages = [];
Vue.prototype.$message = { closeAll() {}, success: (t) => messages.push(['ok', t]), error: (t) => messages.push(['error', t]) };
let spinner = 0;
const loading = function () { spinner++; };
loading.close = () => { spinner--; };
Vue.prototype.$globalLoading = loading;

const calls = [];
let answers = {};
global.window = {
	$rpcRequest(kind, params) {
		assert.strictEqual(kind, 'call');
		const [sid, object, method, args] = params;
		assert.strictEqual(sid, 'sid');
		assert.strictEqual(object, 'mudi-volte');
		calls.push([method, args]);
		const a = answers[method];
		return a instanceof Error ? Promise.reject(a) : Promise.resolve(typeof a === 'function' ? a(args) : a);
	}
};
global.document = { getElementById: () => null, createElement: () => ({}), head: { appendChild() {} } };

const timers = [];
const polls = new Map(); // the page's live intervals: handle -> {fn, ms}
const realSetInterval = global.setInterval;
const realClearInterval = global.clearInterval;
global.setInterval = (fn, ms) => {
	timers.push(ms);
	const t = realSetInterval(() => {}, 1 << 30);
	polls.set(t, { fn, ms });
	return t;
};
global.clearInterval = (t) => { polls.delete(t); realClearInterval(t); };

// The panel: axios.get(...).then(res => eval(res.data)).
const source = fs.readFileSync(path.join(__dirname, '../files/www/views/gl-sdk4-ui-mudi-volte.common.js'), 'utf8');
const page = eval(source); // eslint-disable-line no-eval
assert.strictEqual(page.name, 'mudi-volte');
assert.strictEqual(typeof page.render, 'function');

const renderer = createRenderer();
const settle = () => new Promise((r) => setImmediate(r)).then(() => new Promise((r) => setImmediate(r)));

// jobPoll runs the page's poll of a background run (setup, give_back) once;
// false when the page polls none.
async function jobPoll() {
	const p = [...polls.values()].filter((x) => x.ms === 3000);
	assert.ok(p.length <= 1, 'one poll of a background run at most');
	if (!p.length)
		return false;
	p[0].fn();
	await settle();
	return true;
}

// confirmed runs an action of the page and answers its question with Continue.
async function confirmed(vm, action) {
	vm[action]();
	vm.confirm.action();
	vm.confirm = null;
	await settle();
}

const status = {
	version: '0.1.0', enabled: true, alive: true, lan_ip: '192.168.8.1',
	settings: { incoming: 'all', allow: [], dial: '*', country: '44', ring_sec: 45, sms: true, encryption: true },
	phones: [{ user: 'pixel', ext: '201' }, { user: 'iphone', ext: '202' }],
	push: { login: 'myname', password_set: true, phones: ['iphone', 'pixel'] },
	missed: [{ time: '2026-11-06T13:20:46+01:00', from: '+447700900789', reason: 'no-phone' }],
	state: { phase: 'registered', registered: true, number: '+447700900000', rat: 'LTE', interface: 'rmnet_data1',
		phones: ['pixel', 'iphone'], phones_tls: ['pixel'], since: '2026-11-06T17:08:32+01:00', updated_at: '2026-11-06T18:08:32+01:00', restarts: 0 }
};

async function main() {
	answers = {
		get_status: status,
		get_sms: { list: [{ time: '2026-11-06T13:21:30+01:00', from: 'Operator', text: 'Hello\nworld', via: 'modem' }] },
		get_phone: (a) => ({ ok: true, user: a.name, password: 'secret-password', ext: '201', domain: '192.168.8.1',
			transport: 'TLS on port 5061 with SRTP media encryption, or UDP on port 5060 without encryption',
			url: 'http://192.168.8.1:8060/p/abc', svg: '<svg id="qr"></svg>' }),
		set_config: { ok: true },
		add_phone: (a) => (a.name === 'taken' ? { ok: false, error: 'phone "taken" exists' } : { ok: true }),
		del_phone: { ok: true },
		clear_missed: { ok: true },
		set_push: { ok: true },
		restart: { ok: true }
	};
	const vm = new Vue(page);
	await settle();
	assert.deepStrictEqual(timers.sort(), [30000, 5000]);
	let html = await renderer.renderToString(vm);
	for (const want of ['Calls &amp; SMS', 'Online, calls work', '+447700900000', 'LTE, IMS rmnet_data1', 'for 1 h 0 min',
		'Missed calls', '+447700900789', 'No phone was connected', 'Clear the list',
		'Operator', 'Hello\nworld', 'New SMS also go to every phone',
		'pixel', 'iphone', '201', 'Connect / QR code', 'Add phone', 'Settings', 'Ring time, seconds', 'data-state="success"',
		'yes, encrypted', 'Encrypted calls', 'SIP over TLS and SRTP audio']) {
		assert.ok(html.includes(want.replace(/\n/g, '\n')), 'page lacks ' + JSON.stringify(want));
	}
	assert.ok(!html.includes('Allowed callers'), 'the allow list shows only for incoming=allow');
	assert.ok(!html.includes('Restarts after a crash'), 'no crash, no row');

	// Pushes: the account and the phones; the saved password never reaches the page.
	assert.ok(html.includes('Push notifications') && html.includes('Phones that can be woken: iphone, pixel') &&
		html.includes('Saved; leave empty to keep it') && html.includes('value="myname"'), 'push card');
	assert.deepStrictEqual(vm.pushForm, { login: 'myname', password: '' });
	vm.pushForm.login = 'other@sip.linphone.org';
	vm.pushForm.password = 'secret "pw"';
	vm.savePush();
	await settle();
	assert.deepStrictEqual(calls.filter((c) => c[0] === 'set_push').pop()[1], { login: 'other', password: 'secret "pw"' });
	assert.strictEqual(vm.pushForm.password, '', 'the typed password is dropped after saving');
	vm.pushForm.login = 'no spaces';
	const pushCalls = calls.length;
	vm.savePush();
	assert.strictEqual(calls.length, pushCalls, 'a bad login never reaches the router');
	assert.ok(messages.pop()[0] === 'error');
	vm.pushForm = null;

	// The QR dialog of a phone.
	vm.showPhone('pixel');
	await settle();
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('Connect the phone &quot;pixel&quot;') && html.includes('<svg id="qr"></svg>') &&
		html.includes('secret-password') && html.includes('http://192.168.8.1:8060/p/abc') &&
		html.includes('TLS on port 5061 with SRTP media encryption'), 'phone dialog');
	// The panel's theme gives the dialog body no padding: the content goes into
	// a .dialog-main like on its own pages, the buttons into one row.
	assert.ok(html.includes('<h3>Connect the phone &quot;pixel&quot;</h3><div class="dialog-main"><ol>'), 'dialog body in .dialog-main');
	assert.ok(/<footer><div class="mv-btns"><button[^>]*>Show on the router's display<\/button><button data-type="primary"[^>]*>Close<\/button><\/div><\/footer>/.test(html),
		'dialog buttons in one row, nothing between them: ' + (html.match(/<footer>.*?<\/footer>/) || [''])[0]);
	assert.strictEqual(spinner, 0, 'spinner closed');
	vm.phone = null;

	// Settings: the allow list is split, the numbers become numbers.
	vm.form.incoming = 'allow';
	vm.form.allow = '+447700900789,  +447700900123 ';
	vm.form.ring_sec = '30';
	vm.form.sms = false;
	vm.form.encryption = false;
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('Allowed callers'));
	vm.saveSettings();
	await settle();
	const set = calls.filter((c) => c[0] === 'set_config').pop();
	assert.deepStrictEqual(set[1], { incoming: 'allow', allow: ['+447700900789', '+447700900123'], dial: '*', country: '44', ring_sec: 30, sms: false, encryption: false, plain: true });
	assert.ok(!html.includes('SIP without encryption'), 'the plain-SIP switch shows only with encryption on');
	vm.form.encryption = true;
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('SIP without encryption'), 'the plain-SIP switch shows with encryption on');
	assert.ok(messages.some((m) => m[0] === 'ok' && /restarts/.test(m[1])));

	// A bad name never reaches the router; a refusal shows the router's words.
	const before = calls.length;
	vm.newPhone = 'no spaces';
	vm.addPhone();
	assert.strictEqual(calls.length, before);
	assert.ok(messages.pop()[0] === 'error');
	vm.newPhone = 'taken';
	vm.addPhone();
	await settle();
	assert.deepStrictEqual(messages.pop(), ['error', 'phone "taken" exists']);
	assert.strictEqual(spinner, 0);

	// Removing asks first.
	vm.delPhone('iphone');
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('Remove the phone &quot;iphone&quot;?'));
	assert.ok(/<div class="dialog-main"><p>Remove the phone[^<]*<\/p><\/div><footer><div class="mv-btns"><button[^>]*>Cancel<\/button><button data-type="primary"[^>]*>Continue<\/button><\/div><\/footer>/.test(html),
		'confirm dialog built the same way');
	assert.ok(!calls.some((c) => c[0] === 'del_phone'));
	vm.confirm.action();
	vm.confirm = null;
	await settle();
	assert.deepStrictEqual(calls.filter((c) => c[0] === 'del_phone').pop()[1], { name: 'iphone' });

	// Not set up yet: only the setup.
	answers.get_status = Object.assign({}, status, { enabled: false, state: undefined, alive: false });
	await vm.refresh();
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('Set up and restart the router') && !html.includes('Missed calls'));

	// Setup goes on in the background; the page polls its log and state. A
	// modem that refuses a value ends it with the reason and no restart.
	answers.setup = { ok: true };
	answers.get_setup_log = { log: 'Checking the router, the modem and the SIM...\n', state: 'running 4242' };
	await confirmed(vm, 'startSetup');
	assert.ok(await jobPoll(), 'the page polls the setup');
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('Checking the router, the modem and the SIM') && html.includes('If the router restarts'), 'setup running');
	assert.ok(html.includes('disabled="disabled">Set up and restart the router'), 'no second setup meanwhile');
	const refusal = 'setup stopped: the modem did not take all the settings that calls need';
	answers.get_setup_log = {
		log: 'Checking the router, the modem and the SIM...\nmudi-volte: the modem refused AT+QNWPREFCFG="voice_domain",1\nmudi-volte: ' + refusal + '\n',
		state: 'exit 1'
	};
	assert.ok(await jobPoll());
	assert.ok(!(await jobPoll()), 'the poll stops when the run ends');
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('<p class="mv-bad">Setup failed: ' + refusal + '</p>'), 'the reason of a failed setup');
	assert.ok(html.includes('refused AT+QNWPREFCFG=&quot;voice_domain&quot;,1'), 'the log stays');
	assert.ok(!/restarts now/.test(html), 'a failed setup promises no restart');
	assert.ok(!html.includes('disabled="disabled">Set up'), 'setup may be tried again');
	assert.deepStrictEqual(messages.pop(), ['error', 'Setup failed: ' + refusal]);

	// The switch enables the service just before the restart: the setup card
	// stays and says that the router restarts only when it does.
	answers.get_setup_log = { log: '', state: 'running' };
	await confirmed(vm, 'startSetup');
	answers.get_status = Object.assign({}, status, { enabled: true, alive: false });
	await vm.refresh();
	assert.ok(await jobPoll());
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('If the router restarts') && !html.includes('Missed calls'), 'the setup keeps its card');
	answers.get_setup_log = { log: 'Restarting now.\n', state: 'restarting' };
	assert.ok(await jobPoll());
	assert.ok(!(await jobPoll()));
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('The router restarts now') && html.includes('Restarting now.'), 'the restart announced');

	// "Restore and restart": the page announces no restart until the modem
	// has taken its values; a refusal shows its reason, the line stays.
	vm.job = null;
	answers.get_status = status;
	await vm.refresh();
	answers.give_back = { ok: true };
	answers.get_setup_log = { log: '', state: 'running' };
	await confirmed(vm, 'giveBack');
	assert.ok(await jobPoll(), 'the page polls the restore');
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('Giving VoLTE back to the modem') && html.includes('disabled="disabled">Restore and restart'), 'restore running');
	assert.ok(!html.includes('The router restarts with') && !messages.some((m) => /restarts/.test(m[1]) && /modem/.test(m[1])),
		'no restart announced before the modem took its values');
	const kept = 'the modem\'s own VoLTE is not restored; the service, the package and the settings are kept: retry when the modem answers';
	answers.get_setup_log = {
		log: 'mudi-volte: could not restore ue_usage_setting 0\nmudi-volte: the values written so far are set back: the modem stays in External VoLTE mode\nmudi-volte: ' + kept + '\n',
		state: 'exit 1'
	};
	assert.ok(await jobPoll());
	assert.ok(!(await jobPoll()));
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('<p class="mv-bad">VoLTE is not given back to the modem: ' + kept + '</p>'), 'the reason of a failed restore');
	assert.ok(html.includes('could not restore ue_usage_setting 0') && html.includes('Missed calls'), 'the log, and the line still on the page');
	assert.ok(!html.includes('The router restarts'), 'a failed restore promises no restart');
	assert.deepStrictEqual(messages.pop(), ['error', 'VoLTE is not given back to the modem: ' + kept]);

	// The restore switches the service off before the restart: the page keeps
	// its card instead of offering the setup, then announces the restart.
	answers.get_setup_log = { log: '', state: 'running' };
	await confirmed(vm, 'giveBack');
	answers.get_status = Object.assign({}, status, { enabled: false, state: undefined, alive: false });
	await vm.refresh();
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('Giving VoLTE back to the modem') && !html.includes('Set up and restart the router'), 'the restore keeps its card');
	answers.get_setup_log = { log: 'Restarting the router...\n', state: 'restarting' };
	assert.ok(await jobPoll());
	assert.ok(!(await jobPoll()));
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('The router restarts with the modem\'s own VoLTE'), 'the restart announced');
	vm.job = null;
	answers.get_status = status;

	// Pushes off, no phones yet (cjson sends an empty list as {}).
	answers.get_status = Object.assign({}, status, { push: { login: '', password_set: false, phones: {} } });
	vm.pushForm = null;
	await vm.refresh();
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('Pushes are off') && !html.includes('Turn off'), 'push card when off');

	// The service stopped: said plainly.
	answers.get_status = Object.assign({}, status, { alive: false });
	await vm.refresh();
	html = await renderer.renderToString(vm);
	assert.ok(html.includes('The service is not running') && html.includes('data-state="no"'));

	// A daemon that keeps crashing: procd starts it again, the page says how often.
	answers.get_status = Object.assign({}, status, { state: Object.assign({}, status.state, { crash_restarts: 3 }) });
	await vm.refresh();
	html = await renderer.renderToString(vm);
	assert.ok(/Restarts after a crash<\/td><td[^>]*>3 in a row/.test(html), 'crash restarts shown');

	// The router does not answer when the page opens.
	answers.get_status = new Error('timeout');
	const fresh = new Vue(page);
	await settle();
	html = await renderer.renderToString(fresh);
	assert.ok(html.includes('Cannot reach the mudi-volte service'));

	assert.deepStrictEqual(warnings, [], 'Vue warnings');
	console.log('gl-view: ok');
	process.exit(0);
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
