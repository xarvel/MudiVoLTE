// MudiVoLTE in the GL.iNet admin panel (firmware 4.x): Applications > Phone
// calls. The panel fetches this file by the view name of the menu entry
// (/usr/share/oui/menu.d/mudi-volte.json) and evaluates it; the value of the
// expression is the page, a Vue 2 component. It uses the panel's own parts
// (gl-title, gl-card, gl-button, gl-switch, Element's el-dialog, el-input,
// el-select) and its RPC: window.$rpcRequest → /rpc → the Lua module
// /usr/lib/oui-httpd/rpc/mudi-volte, which runs the mudi-volte command line
// tool. The same as the LuCI page, for routers without LuCI.
(function () {
	'use strict';

	var STYLE_ID = 'mudi-volte-style';
	var CSS = [
		'.mudi-volte .gl-card-wrapper{margin-bottom:16px}',
		'.mudi-volte .mv-table,.mv-dialog .mv-table{width:100%;border-collapse:collapse;font-size:14px}',
		'.mudi-volte .mv-table th{text-align:left;font-weight:500;opacity:.6;padding:8px 6px;border-bottom:1px solid rgba(128,128,128,.25)}',
		'.mudi-volte .mv-table td,.mv-dialog .mv-table td{padding:8px 6px;border-bottom:1px solid rgba(128,128,128,.12);vertical-align:top}',
		'.mudi-volte .mv-table td.mv-text{white-space:pre-wrap;word-break:break-word}',
		'.mudi-volte .mv-rows td:first-child,.mv-dialog .mv-rows td:first-child{width:35%;opacity:.7}',
		'.mudi-volte .mv-note,.mv-dialog .mv-note{font-size:12px;opacity:.65;margin:10px 0 0;line-height:1.5}',
		'.mudi-volte .mv-actions{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;align-items:center}',
		// The theme gives .gl-btn "margin: 0 10px": inside our rows the gap alone
		// spaces the buttons, so that they line up with the card's edges.
		'.mudi-volte .mv-actions .gl-btn,.mudi-volte .mv-add .gl-btn,.mudi-volte .mv-phone-acts .gl-btn{margin:0;white-space:nowrap}',
		// Phones: one row each, the buttons wrap under the name on a narrow screen.
		'.mudi-volte .mv-phone{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;padding:10px 6px;border-bottom:1px solid rgba(128,128,128,.12)}',
		'.mudi-volte .mv-phone-info{flex:1 1 200px;min-width:0}',
		'.mudi-volte .mv-phone-name{font-weight:500}',
		'.mudi-volte .mv-phone-meta{font-size:12px;opacity:.7;margin-top:2px}',
		'.mudi-volte .mv-phone-acts{display:flex;gap:8px;margin-left:auto}',
		'.mudi-volte .mv-add{display:flex;gap:8px;align-items:center;margin-top:14px;max-width:420px}',
		'.mudi-volte .mv-add .el-input{flex:1 1 auto;min-width:0}',
		'.mudi-volte .mv-ok{color:#2ba245;font-weight:500}',
		'.mudi-volte .mv-warn{color:#e6a23c;font-weight:500}',
		'.mudi-volte .mv-bad{color:#f56c6c;font-weight:500}',
		'.mudi-volte .mv-form-row{display:flex;align-items:center;gap:12px;margin:10px 0;flex-wrap:wrap}',
		'.mudi-volte .mv-form-row>label{width:35%;min-width:160px;opacity:.8}',
		'.mudi-volte .mv-form-row>.mv-field{flex:1;min-width:200px}',
		'.mudi-volte pre.mv-log{max-height:25em;overflow:auto;font-size:12px;white-space:pre-wrap;background:rgba(128,128,128,.08);padding:8px;margin:10px 0 0}',
		// Dialogs are appended to <body>, outside .mudi-volte. The panel's theme
		// gives the dialog body no padding (its own pages put a .dialog-main
		// inside, at most 55vh), centers the dialog in a wrapper that does not
		// scroll and centers the footer as a flex row. Element's bottom margin of
		// 50px would push a tall dialog's title off the top of a phone screen.
		'.el-dialog__wrapper .el-dialog.mv-dialog{margin-bottom:0}',
		'.el-dialog__wrapper .el-dialog.mv-dialog .el-dialog__body .dialog-main{max-height:calc(100vh - 200px);max-height:calc(100dvh - 200px)}',
		'.mv-dialog .dialog-main p{margin:0 0 10px;line-height:1.5}',
		'.mv-dialog .dialog-main>:last-child{margin-bottom:0}',
		'.mv-dialog .mv-btns{display:flex;flex-wrap:wrap;justify-content:center;align-items:center;gap:12px;padding:12px 0;width:100%}',
		'.mv-dialog .mv-btns .gl-btn{min-width:100px;margin:0}',
		'.mv-dialog .mv-qr{text-align:center;margin:4px 0 14px}',
		'.mv-dialog .mv-qr>div{display:inline-block;width:240px;height:240px;background:#fff;padding:8px}',
		'.mv-dialog .mv-qr svg{width:100%;height:100%}',
		'.mv-dialog code{word-break:break-all}',
		'.mv-dialog ol{margin:0 0 10px;padding-left:20px;line-height:1.6;list-style:decimal}'
	].join('\n');

	var phases = {
		starting: 'starting',
		modem: 'waiting for the modem and 4G',
		pdn: 'opening the connection to the operator',
		registering: 'registering with the operator',
		recovering: 'recovering after a failure',
		'radio-restart': 'restarting the radio',
		stopped: 'stopped'
	};

	var missedReasons = {
		'no-phone': 'No phone was connected',
		'no-answer': 'Nobody answered',
		'caller-hung-up': 'The caller hung up before the answer',
		declined: 'Declined on a phone',
		busy: 'A phone was busy',
		'line-busy': 'The line was busy with another call',
		'not-allowed': 'Not in the list of allowed callers',
		error: 'Error, see the service log'
	};

	// The background runs of setup and give_back, as the page tells them.
	var jobTexts = {
		setup: {
			running: 'If the router restarts, reconnect to its Wi-Fi in 2-3 minutes and open this page again.',
			restarting: 'The router restarts now: reconnect to its Wi-Fi in 2-3 minutes and open this page again.',
			failed: 'Setup failed: '
		},
		give_back: {
			running: 'Giving VoLTE back to the modem. Once the modem has taken its settings, the router restarts.',
			restarting: 'The router restarts with the modem\'s own VoLTE. Reconnect in 2-3 minutes.',
			failed: 'VoLTE is not given back to the modem: '
		}
	};

	function rpc(method, params) {
		return window.$rpcRequest('call', ['sid', 'mudi-volte', method, params || {}]);
	}

	// jobState: how a background run goes, from the state of get_setup_log:
	// 'running', 'restarting' (the router restarts now) or its exit code.
	function jobState(s) {
		s = String(s || '').trim();
		var m = /^exit (\d+)$/.exec(s);
		if (m)
			return Number(m[1]);
		return s === 'restarting' ? s : 'running';
	}

	// jobError: why a run failed: the last line the tool wrote to stderr
	// ("mudi-volte: ..."), or its exit code.
	function jobError(log, code) {
		var lines = String(log || '').split('\n').filter(function (l) { return /^mudi-volte: /.test(l); });
		return lines.length ? lines[lines.length - 1].replace(/^mudi-volte: /, '') : 'exit code ' + code;
	}

	// act runs an action that answers {ok, error}: an error becomes a rejection.
	function act(method, params) {
		return rpc(method, params).then(function (res) {
			if (!res || res.ok === false)
				throw new Error((res && res.error) || 'failed');
			return res;
		});
	}

	function when(iso) {
		var t = new Date(Date.parse(iso));
		return isNaN(t) ? (iso || '') : t.toLocaleString();
	}

	function duration(from, to) {
		var s = Math.max(0, Math.floor((Date.parse(to) - Date.parse(from)) / 1000));
		if (isNaN(s))
			return '';
		if (s < 60)
			return s + ' s';
		if (s < 3600)
			return Math.floor(s / 60) + ' min';
		if (s < 86400)
			return Math.floor(s / 3600) + ' h ' + Math.floor(s % 3600 / 60) + ' min';
		return Math.floor(s / 86400) + ' d ' + Math.floor(s % 86400 / 3600) + ' h';
	}

	function injectStyle() {
		if (document.getElementById(STYLE_ID))
			return;
		var el = document.createElement('style');
		el.id = STYLE_ID;
		el.textContent = CSS;
		document.head.appendChild(el);
	}

	return {
		name: 'mudi-volte',

		data: function () {
			return {
				loaded: false,
				status: null,
				sms: [],
				form: null, // the settings being edited
				pushForm: null, // the linphone.org account being edited: login, password (empty = keep)
				saving: false,
				newPhone: '',
				busy: false,
				phone: null, // the phone shown in the dialog
				confirm: null, // {text, action}
				log: '',
				logShown: false,
				job: null // the background run of setup or give_back: {action, state, log, error}
			};
		},

		created: function () {
			injectStyle();
			var self = this;
			this.refresh();
			this.loadSMS();
			this.timer = setInterval(function () { self.refresh(); }, 5000);
			this.smsTimer = setInterval(function () { self.loadSMS(); }, 30000);
		},

		destroyed: function () {
			clearInterval(this.timer);
			clearInterval(this.smsTimer);
			clearInterval(this.jobTimer);
		},

		methods: {
			refresh: function () {
				var self = this;
				return rpc('get_status').then(function (st) {
					self.status = st;
					self.loaded = true;
					if (!self.form && st && st.settings)
						self.form = self.formFrom(st.settings);
					if (!self.pushForm && st)
						self.pushForm = { login: (st.push && st.push.login) || '', password: '' };
				}).catch(function () {
					self.loaded = true;
				});
			},

			loadSMS: function () {
				var self = this;
				return rpc('get_sms').then(function (res) {
					self.sms = (res && res.list) || [];
				}).catch(function () {});
			},

			formFrom: function (s) {
				return {
					incoming: s.incoming || 'all',
					allow: (s.allow || []).join(' '),
					dial: s.dial || '*',
					country: s.country || '',
					ring_sec: String(s.ring_sec || 45),
					sms: s.sms !== false,
					encryption: s.encryption !== false,
					plain: s.plain !== false
				};
			},

			fail: function (e) {
				this.$message.closeAll();
				this.$message.error(String((e && e.message) || e || 'failed'));
			},

			done: function (text) {
				this.$message.closeAll();
				this.$message.success(text);
			},

			ask: function (text, action) {
				this.confirm = { text: text, action: action };
			},

			clearMissed: function () {
				var self = this;
				act('clear_missed').then(function () {
					self.done('The list is empty.');
					self.refresh();
				}).catch(this.fail);
			},

			showPhone: function (user) {
				var self = this;
				this.loading(true);
				act('get_phone', { name: user }).then(function (res) {
					self.phone = res;
				}).catch(this.fail).then(function () {
					self.loading(false);
				});
			},

			// loading shows the panel's own spinner, as its pages do.
			loading: function (on) {
				var g = this.$globalLoading;
				if (typeof g !== 'function')
					return;
				if (on)
					g.call(this);
				else if (typeof g.close === 'function')
					g.close();
			},

			screenPhone: function (user) {
				var self = this;
				act('screen_phone', { name: user }).then(function (res) {
					self.done(res.output || 'Shown on the router\'s display.');
				}).catch(this.fail);
			},

			addPhone: function () {
				var name = (this.newPhone || '').trim();
				if (!/^[A-Za-z0-9._-]{1,32}$/.test(name)) {
					this.fail('Phone name: up to 32 letters, digits, dots, dashes or underscores.');
					return;
				}
				var self = this;
				this.busy = true;
				this.loading(true);
				act('add_phone', { name: name }).then(function () {
					self.newPhone = '';
					self.loading(false);
					return self.refresh().then(function () { self.showPhone(name); });
				}).catch(function (e) {
					self.loading(false);
					self.fail(e);
				}).then(function () { self.busy = false; });
			},

			delPhone: function (user) {
				var self = this;
				this.ask('Remove the phone "' + user + '"? It can no longer sign in.', function () {
					self.busy = true;
					act('del_phone', { name: user }).then(function () {
						self.done('Removed.');
						return self.refresh();
					}).catch(self.fail).then(function () { self.busy = false; });
				});
			},

			saveSettings: function () {
				var f = this.form, self = this;
				var params = {
					incoming: f.incoming,
					allow: f.allow.split(/[\s,]+/).filter(function (v) { return v !== ''; }),
					dial: f.dial,
					country: f.country,
					ring_sec: parseInt(f.ring_sec, 10),
					sms: !!f.sms,
					encryption: !!f.encryption,
					plain: !!f.plain
				};
				this.saving = true;
				act('set_config', params).then(function () {
					self.done('Saved. The service restarts: calls are offline for about 10 seconds.');
					self.form = null;
					return self.refresh();
				}).catch(this.fail).then(function () { self.saving = false; });
			},

			savePush: function () {
				var f = this.pushForm, self = this;
				var login = (f.login || '').trim().replace(/@sip\.linphone\.org$/, '');
				if (!/^[A-Za-z0-9._+-]{1,64}$/.test(login)) {
					this.fail('Login: the name of the linphone.org account, without @sip.linphone.org.');
					return;
				}
				this.saving = true;
				act('set_push', { login: login, password: f.password || '' }).then(function () {
					self.done('Saved. The service restarts: calls are offline for about 10 seconds.');
					self.pushForm = null;
					return self.refresh();
				}).catch(this.fail).then(function () { self.saving = false; });
			},

			pushOff: function () {
				var self = this;
				this.ask('Turn pushes off? iPhones then get calls only while Linphone is open, Android phones while its service runs.', function () {
					self.saving = true;
					act('set_push', { login: '' }).then(function () {
						self.done('Pushes off. The service restarts: calls are offline for about 10 seconds.');
						self.pushForm = null;
						return self.refresh();
					}).catch(self.fail).then(function () { self.saving = false; });
				});
			},

			restart: function () {
				var self = this;
				act('restart').then(function () {
					self.done('Restarting: calls are offline for about 10 seconds.');
				}).catch(this.fail);
			},

			showLog: function () {
				var self = this;
				rpc('get_log').then(function (res) {
					self.log = (res && res.log) || 'The log is empty.';
					self.logShown = true;
				}).catch(this.fail);
			},

			startSetup: function () {
				var self = this;
				this.ask('The modem\'s own VoLTE gets switched off and the router restarts once: Wi-Fi and the internet are down for 2-3 minutes. Continue?', function () {
					act('setup').then(function () {
						self.watchJob('setup');
					}).catch(self.fail);
				});
			},

			giveBack: function () {
				var self = this;
				this.ask('Give VoLTE back to the modem and restart the router? Calls through this router stop until you run the setup again.', function () {
					act('give_back').then(function () {
						self.watchJob('give_back');
					}).catch(self.fail);
				});
			},

			// watchJob follows the background run of setup or give_back until it
			// fails, the router restarts or it is done. The router restarts only
			// once the modem has taken every value; a refusal ends the run with
			// its reason, and the router keeps running.
			watchJob: function (action) {
				var self = this;
				clearInterval(this.jobTimer);
				var job = this.job = { action: action, state: 'running', log: '', error: '' };
				var timer = this.jobTimer = setInterval(function () {
					rpc('get_setup_log').then(function (res) {
						if (self.job !== job || job.state !== 'running')
							return;
						var state = jobState(res && res.state);
						job.log = (res && res.log) || '';
						if (state === 'running')
							return;
						clearInterval(timer);
						if (state === 'restarting') {
							job.state = state;
						} else if (state === 0) {
							job.state = 'done';
							self.refresh();
						} else {
							job.state = 'failed';
							job.error = jobError(job.log, state);
							self.fail(jobTexts[action].failed + job.error);
							self.refresh();
						}
					}).catch(function () {}); // the router is restarting
				}, 3000);
			},

			jobBusy: function () {
				return !!this.job && (this.job.state === 'running' || this.job.state === 'restarting');
			},

			// --- rendering ---

			table: function (h, heads, rows) {
				return h('table', { 'class': 'mv-table' }, [
					h('thead', [h('tr', heads.map(function (t) { return h('th', t); }))]),
					h('tbody', rows)
				]);
			},

			button: function (h, text, click, opts) {
				opts = opts || {};
				var attrs = { disabled: !!opts.disabled };
				if (opts.type)
					attrs.type = opts.type;
				return h('gl-button', { attrs: attrs, on: { click: click } }, text);
			},

			// dialog is an el-dialog built like the panel's own: the body inside a
			// .dialog-main, the buttons in one row; close runs on the × and Esc.
			dialog: function (h, title, width, body, buttons, close) {
				return h('el-dialog', {
					props: { visible: true, title: title, width: width, appendToBody: true, customClass: 'mv-dialog' },
					on: { 'update:visible': function (v) { if (!v) close(); } }
				}, [
					h('div', { 'class': 'dialog-main' }, body),
					h('div', { slot: 'footer', 'class': 'mv-btns' }, buttons.filter(Boolean))
				]);
			},

			renderStatus: function (h) {
				var s = this.status, st = s.state;
				var rows = [];
				var row = function (label, value) { rows.push(h('tr', [h('td', label), h('td', [value])])); };
				var state;
				if (!st || !s.alive) {
					state = h('span', { 'class': 'mv-bad' }, 'The service is not running');
				} else if (st.registered) {
					state = h('span', { 'class': 'mv-ok' }, 'Online, calls work');
				} else {
					state = h('span', { 'class': 'mv-warn' }, 'Connecting: ' + (phases[st.phase] || st.phase || ''));
				}
				row('Status', h('span', [state, st && st.since ? h('small', { style: 'opacity:.6' }, ' for ' + duration(st.since, st.updated_at)) : '']));
				if (st) {
					row('Phone number', st.number || '—');
					row('Mobile network', st.rat ? st.rat + ', IMS ' + (st.interface || '') : '—');
					row('Phones connected', (st.phones && st.phones.length) ? st.phones.join(', ') : 'none');
					if (s.missed && s.missed.length)
						row('Missed calls', h('strong', String(s.missed.length)));
					if (st.restarts > 0)
						row('Reconnects to the operator', String(st.restarts));
					if (st.crash_restarts > 0)
						row('Restarts after a crash', st.crash_restarts + ' in a row');
					if (st.last_error)
						row('Last error', h('small', st.last_error));
				}
				var stateDot = !st || !s.alive ? 'no' : (st.registered ? 'success' : 'warn');
				return h('gl-card', { attrs: { title: 'Status', state: stateDot } }, [
					h('table', { 'class': 'mv-table mv-rows' }, [h('tbody', rows)]),
					h('div', { 'class': 'mv-actions' }, [this.button(h, 'Restart the service', this.restart)]),
					!st || !s.alive ? h('p', { 'class': 'mv-note' }, 'It starts by itself after setup; the service log below tells why it stopped.') : ''
				]);
			},

			renderMissed: function (h) {
				var list = this.status.missed || [];
				var body = list.length
					? this.table(h, ['Time', 'From', 'Why it was missed'], list.map(function (m) {
						return h('tr', [h('td', when(m.time)), h('td', m.from || 'withheld'), h('td', missedReasons[m.reason] || m.reason || '')]);
					}))
					: h('p', 'No missed calls.');
				return h('gl-card', { attrs: { title: 'Missed calls' } }, [
					body,
					list.length ? h('div', { 'class': 'mv-actions' }, [this.button(h, 'Clear the list', this.clearMissed)]) : '',
					h('p', { 'class': 'mv-note' }, 'Incoming calls that no phone answered. Calls cannot reach the router while it has no 4G or is offline; such calls do not show up here.')
				]);
			},

			renderSMS: function (h) {
				var sms = this.sms || [];
				var body = sms.length
					? this.table(h, ['Time', 'From', 'Message'], sms.map(function (m) {
						return h('tr', [h('td', when(m.time)), h('td', m.from || ''), h('td', { 'class': 'mv-text' }, m.text || '')]);
					}))
					: h('p', 'No SMS.');
				var on = this.status.settings && this.status.settings.sms;
				return h('gl-card', { attrs: { title: 'SMS' } }, [
					body,
					h('p', { 'class': 'mv-note' }, (on
						? 'New SMS also go to every phone as messages (the chat in Linphone); a message from a phone to a number goes out as an SMS. '
						: 'SMS stay on the router (SMS on the phones is off in the settings). ') +
						'The SMS page of this admin panel keeps the messages the modem received: delete them there.')
				]);
			},

			renderPhones: function (h) {
				var self = this, s = this.status;
				var online = (s.state && s.state.phones) || [];
				var secure = (s.state && s.state.phones_tls) || [];
				var phones = s.phones || [];
				var body = phones.length
					? h('div', { 'class': 'mv-phones' }, phones.map(function (p) {
						var conn = secure.indexOf(p.user) >= 0 ? 'yes, encrypted' : online.indexOf(p.user) >= 0 ? 'yes' : 'no';
						return h('div', { 'class': 'mv-phone' }, [
							h('div', { 'class': 'mv-phone-info' }, [
								h('div', { 'class': 'mv-phone-name' }, p.user),
								h('div', { 'class': 'mv-phone-meta' }, (p.ext ? 'Short number ' + p.ext : 'No short number') + ' · connected: ' + conn)
							]),
							h('div', { 'class': 'mv-phone-acts' }, [
								self.button(h, 'Connect / QR code', function () { self.showPhone(p.user); }, { type: 'primary' }),
								self.button(h, 'Remove', function () { self.delPhone(p.user); }, { disabled: self.busy })
							])
						]);
					}))
					: h('p', 'No phones yet.');
				return h('gl-card', { attrs: { title: 'Phones' } }, [
					body,
					h('div', { 'class': 'mv-add' }, [
						h('el-input', {
							attrs: { placeholder: 'New phone, e.g. pixel', maxlength: 32 },
							model: { value: self.newPhone, callback: function (v) { self.newPhone = v; }, expression: 'newPhone' }
						}),
						this.button(h, 'Add phone', this.addPhone, { type: 'primary', disabled: this.busy })
					]),
					h('p', { 'class': 'mv-note' }, 'An incoming call rings all connected phones; the first to answer gets it. Phones call and message each other by name or short number, for free and without the SIM. Adding or removing a phone restarts the service: calls are offline for about 10 seconds.')
				]);
			},

			formRow: function (h, label, field) {
				return h('div', { 'class': 'mv-form-row' }, [h('label', label), h('div', { 'class': 'mv-field' }, [field])]);
			},

			input: function (h, key, placeholder) {
				var f = this.form;
				return h('el-input', {
					attrs: { placeholder: placeholder || '' },
					model: { value: f[key], callback: function (v) { f[key] = v; }, expression: 'form.' + key }
				});
			},

			renderSettings: function (h) {
				var f = this.form, self = this;
				if (!f)
					return '';
				var rows = [
					this.formRow(h, 'Who may call', h('el-select', {
						model: { value: f.incoming, callback: function (v) { f.incoming = v; }, expression: 'form.incoming' }
					}, [
						h('el-option', { props: { label: 'Everyone', value: 'all' } }),
						h('el-option', { props: { label: 'Only the numbers below; others are declined', value: 'allow' } })
					]))
				];
				if (f.incoming === 'allow')
					rows.push(this.formRow(h, 'Allowed callers', this.input(h, 'allow', 'Full numbers, e.g. +447700900123 +33639981234')));
				rows.push(this.formRow(h, 'Outgoing calls and SMS', this.input(h, 'dial', '* = any number, or prefixes: +44 +33')));
				rows.push(this.formRow(h, 'Country code', this.input(h, 'country', 'For numbers with a leading 0, e.g. 44')));
				rows.push(this.formRow(h, 'Ring time, seconds', this.input(h, 'ring_sec', '45')));
				rows.push(this.formRow(h, 'SMS on the phones', h('gl-switch', {
					model: { value: f.sms, callback: function (v) { f.sms = v; }, expression: 'form.sms' }
				})));
				rows.push(this.formRow(h, 'Encrypted calls', h('gl-switch', {
					model: { value: f.encryption, callback: function (v) { f.encryption = v; }, expression: 'form.encryption' }
				})));
				rows.push(h('p', { 'class': 'mv-note' }, 'SIP over TLS and SRTP audio for phones set up by QR code. A phone set up before calls without encryption until you scan its code again.'));
				if (f.encryption) {
					rows.push(this.formRow(h, 'SIP without encryption', h('gl-switch', {
						model: { value: f.plain, callback: function (v) { f.plain = v; }, expression: 'form.plain' }
					})));
					rows.push(h('p', { 'class': 'mv-note' }, 'UDP and TCP next to TLS, for phones set up by hand or before encryption came. Off: TLS only, every phone is set up by QR code, and nothing a phone signs can be read off the Wi-Fi.'));
				}
				return h('gl-card', { attrs: { title: 'Settings' } }, rows.concat([
					h('div', { 'class': 'mv-actions' }, [
						this.button(h, 'Reset', function () { self.form = self.formFrom(self.status.settings); }),
						this.button(h, 'Apply', this.saveSettings, { type: 'primary', disabled: this.saving })
					]),
					h('p', { 'class': 'mv-note' }, 'Applying restarts the service: calls are offline for about 10 seconds.')
				]));
			},

			// renderPush: the linphone.org account that wakes a sleeping Linphone.
			// The page never gets the saved password, only whether there is one.
			renderPush: function (h) {
				var p = this.status.push || {}, f = this.pushForm, self = this;
				if (!f)
					return '';
				var phones = Array.isArray(p.phones) ? p.phones : [];
				var on = !!p.login;
				var field = function (key, attrs) {
					return h('el-input', {
						attrs: attrs,
						model: { value: f[key], callback: function (v) { f[key] = v; }, expression: 'pushForm.' + key }
					});
				};
				return h('gl-card', { attrs: { title: 'Push notifications', state: on ? 'success' : '' } }, [
					h('p', { 'class': 'mv-note', style: 'margin:0 0 6px' }, 'iOS stops Linphone in the background, and Android may stop it too (battery savers, some phone makers). Then only a push from Linphone\'s makers wakes it for a call. The router asks their server (subscribe.linphone.org) to send it, signed with a free linphone.org account, and only when the phone has no connection: Linphone on Android normally keeps one and rings at once. Only the phone\'s push token and a random call ID leave the router, not the caller\'s number.'),
					this.formRow(h, 'linphone.org login', field('login', { placeholder: 'e.g. myname, without @sip.linphone.org', maxlength: 64 })),
					this.formRow(h, 'Password', field('password', { type: 'password', autocomplete: 'new-password',
						placeholder: on && p.password_set ? 'Saved; leave empty to keep it' : 'The password of that account' })),
					h('p', { 'class': 'mv-note' }, on
						? 'Phones that can be woken: ' + (phones.length ? phones.join(', ') : 'none yet. A phone appears here once its Linphone has signed in.')
						: 'Pushes are off: an iPhone gets calls only while Linphone is open. A free account: subscribe.linphone.org.'),
					h('div', { 'class': 'mv-actions' }, [
						on ? this.button(h, 'Turn off', this.pushOff, { disabled: this.saving }) : '',
						this.button(h, 'Save', this.savePush, { type: 'primary', disabled: this.saving || !(f.login || '').trim() })
					])
				]);
			},

			renderMore: function (h) {
				var log = h('gl-card', { attrs: { title: 'Service log' } }, [
					h('div', { 'class': 'mv-actions', style: 'justify-content:flex-start' }, [
						this.button(h, 'Show the service log', this.showLog)
					]),
					this.logShown ? h('pre', { 'class': 'mv-log' }, this.log) : ''
				]);
				return h('div', [log, this.renderGiveBack(h)]);
			},

			renderGiveBack: function (h) {
				return h('gl-card', { attrs: { title: 'Give VoLTE back to the modem' } }, [
					h('p', 'Restores the modem settings saved during setup and restarts the router. Calls then go to the modem\'s own VoLTE again, and this page offers the setup.'),
					h('div', { 'class': 'mv-actions', style: 'justify-content:flex-start' }, [
						this.button(h, 'Restore and restart', this.giveBack, { type: 'error', disabled: this.jobBusy() })
					]),
					this.renderJob(h, 'give_back')
				]);
			},

			renderSetup: function (h) {
				return h('gl-card', { attrs: { title: 'Set up' } }, [
					h('p', 'Setup checks the router, the modem and the SIM, creates a phone account and switches the modem to its "External VoLTE Stack" mode with voice over IMS only, so that calls to the SIM reach this router and the network never moves them to 3G. The router restarts once (2-3 minutes without Wi-Fi and internet). The SIM\'s operator must offer VoLTE on it.'),
					h('div', { 'class': 'mv-actions', style: 'justify-content:flex-start' }, [
						this.button(h, 'Set up and restart the router', this.startSetup, { type: 'primary', disabled: this.jobBusy() })
					]),
					this.renderJob(h, 'setup')
				]);
			},

			// renderJob: the run of setup or give_back in its card: how it goes, a
			// failure with its reason, and what it printed.
			renderJob: function (h, action) {
				var job = this.job;
				if (!job || job.action !== action || job.state === 'done')
					return '';
				var texts = jobTexts[action];
				var note = job.state === 'failed'
					? h('p', { 'class': 'mv-bad' }, texts.failed + job.error)
					: h('p', { 'class': job.state === 'restarting' ? 'mv-warn' : 'mv-note' }, texts[job.state]);
				return h('div', [note, h('pre', { 'class': 'mv-log' }, job.log || 'Starting…')]);
			},

			renderPhoneDialog: function (h) {
				var p = this.phone, self = this;
				if (!p)
					return '';
				var body = [
					h('ol', [
						h('li', 'Connect the phone to this router\'s Wi-Fi (not the guest network).'),
						h('li', 'Install Linphone: free on Google Play and the App Store.'),
						h('li', 'In Linphone choose "Scan QR code" (in the assistant at first start, or under "Fetch remote configuration") and scan this code. Linphone sets up the account by itself.')
					])
				];
				if (p.svg)
					body.push(h('div', { 'class': 'mv-qr' }, [h('div', { domProps: { innerHTML: p.svg } })]));
				if (p.url) {
					body.push(h('p', ['The same link, to type in instead: ', h('code', p.url)]));
					body.push(h('p', { 'class': 'mv-note' }, 'The link works only on this router\'s network. Do not share it: it signs a phone in.'));
				}
				body.push(h('p', 'By hand, in any SIP app:'));
				body.push(h('table', { 'class': 'mv-table mv-rows' }, [h('tbody', [
					h('tr', [h('td', 'Username'), h('td', [h('code', p.user)])]),
					h('tr', [h('td', 'Password'), h('td', [h('code', p.password || '—')])]),
					h('tr', [h('td', 'Domain'), h('td', [h('code', p.domain)])]),
					h('tr', [h('td', 'Transport'), h('td', p.transport || 'UDP')])
				])]));
				body.push(h('p', p.ext
					? 'Other phones call and message this one by the name "' + p.user + '" or the short number ' + p.ext + '.'
					: 'Other phones call and message this one by the name "' + p.user + '".'));
				body.push(h('p', { 'class': 'mv-note' }, 'Call or message 600 to check the phone without the mobile network: you hear yourself, a message comes back. On Android let Linphone run without battery restrictions, or calls ring late. On an iPhone, calls ring while Linphone is in the background only with a push account (Push notifications on this page); messages arrive while Linphone is open.'));
				var close = function () { self.phone = null; };
				return this.dialog(h, 'Connect the phone "' + p.user + '"', '520px', body, [
					p.url ? this.button(h, 'Show on the router\'s display', function () { self.screenPhone(p.user); }) : null,
					this.button(h, 'Close', close, { type: 'primary' })
				], close);
			},

			renderConfirm: function (h) {
				var c = this.confirm, self = this;
				if (!c)
					return '';
				var close = function () { self.confirm = null; };
				return this.dialog(h, 'Please confirm', '420px', [h('p', c.text)], [
					this.button(h, 'Cancel', close),
					this.button(h, 'Continue', function () { self.confirm = null; c.action(); }, { type: 'primary' })
				], close);
			}
		},

		render: function (h) {
			var title = h('gl-title', { attrs: { title: 'Calls & SMS' } });
			var intro = h('p', { 'class': 'mv-note', style: 'margin:0 0 12px' }, 'Calls and SMS to and from the SIM in this router, on phones connected to its Wi-Fi (Linphone or another SIP app).');
			var dialogs = [this.renderPhoneDialog(h), this.renderConfirm(h)];
			if (!this.loaded)
				return h('div', { 'class': 'mudi-volte' }, [title, h('gl-card', [h('p', 'Loading…')])]);
			if (!this.status)
				return h('div', { 'class': 'mudi-volte' }, [title, h('gl-card', [h('p', { 'class': 'mv-bad' }, 'Cannot reach the mudi-volte service on the router.')])]);
			// A run of setup or give_back keeps its card until it ends, also when
			// it has changed "enabled" on its way.
			var busy = this.jobBusy() ? this.job.action : '';
			if (busy === 'setup' || (!this.status.enabled && busy !== 'give_back'))
				return h('div', { 'class': 'mudi-volte' }, [title, intro, this.renderSetup(h)].concat(dialogs));
			if (!this.status.enabled)
				return h('div', { 'class': 'mudi-volte' }, [title, intro, this.renderGiveBack(h)].concat(dialogs));
			return h('div', { 'class': 'mudi-volte' }, [
				title, intro,
				this.renderStatus(h),
				this.renderMissed(h),
				this.renderSMS(h),
				this.renderPhones(h),
				this.renderPush(h),
				this.renderSettings(h),
				this.renderMore(h)
			].concat(dialogs));
		}
	};
})()
