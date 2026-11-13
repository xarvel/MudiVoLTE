'use strict';
'require view';
'require form';
'require fs';
'require ui';
'require uci';
'require poll';
'require dom';

// mudi-volte in LuCI: status, missed calls, SMS, phones (with the QR code
// for Linphone), settings, first-time setup and the service log. All actions go through
// the mudi-volte command line tool, so the web page and SSH behave the same.
// The GL admin panel has the same page (www/views/gl-sdk4-ui-mudi-volte.common.js).

var STATE = '/var/run/mudi-volte/state.json';
var MISSED = '/etc/mudi-volte/missed.jsonl';
var SETUP_LOG = '/tmp/mudi-volte-setup.log';
var SETUP_STATE = '/tmp/mudi-volte-setup.state';
var CLI = '/usr/sbin/mudi-volte';
var IMSD = '/usr/sbin/mudi-imsd';

var phases = {
	starting: _('starting'),
	modem: _('waiting for the modem and 4G'),
	pdn: _('opening the connection to the operator'),
	registering: _('registering with the operator'),
	recovering: _('recovering after a failure'),
	'radio-restart': _('restarting the radio'),
	stopped: _('stopped')
};

function run(cmd, args) {
	return fs.exec(cmd, args).then(function(res) {
		if (res.code !== 0)
			throw new Error((res.stderr || res.stdout || '').trim() || _('exit code %d').format(res.code));
		return res.stdout || '';
	});
}

// jobState: how the background run of setup or of the restore goes, from its
// state file: 'running', 'restarting' (the router restarts now) or its exit
// code.
function jobState(s) {
	s = String(s || '').trim();
	var m = /^exit (\d+)$/.exec(s);
	if (m)
		return +m[1];
	return s === 'restarting' ? s : 'running';
}

// jobError: why a run failed: the last line the tool wrote to stderr
// ("mudi-volte: ..."), or its exit code.
function jobError(log, code) {
	var lines = String(log || '').split('\n').filter(function(l) { return /^mudi-volte: /.test(l); });
	return lines.length ? lines[lines.length - 1].replace(/^mudi-volte: /, '') : _('exit code %d').format(code);
}

// readState: the daemon's state file plus whether the daemon is alive
// (mudi-imsd status: 0 registered, 1 running, 3 not running).
function readState() {
	return Promise.all([
		L.resolveDefault(fs.read(STATE), null),
		L.resolveDefault(fs.exec(IMSD, [ 'status' ]), null)
	]).then(function(r) {
		var st = null;
		try { st = r[0] ? JSON.parse(r[0]) : null; } catch (e) { st = null; }
		if (st)
			st.alive = r[1] != null && r[1].code !== 3;
		return st;
	});
}

var missedReasons = {
	'no-phone': _('No phone was connected'),
	'no-answer': _('Nobody answered'),
	'caller-hung-up': _('The caller hung up before the answer'),
	declined: _('Declined on a phone'),
	busy: _('A phone was busy'),
	'line-busy': _('The line was busy with another call'),
	'not-allowed': _('Not in the list of allowed callers'),
	error: _('Error, see the service log')
};

// readMissed: the daemon's list of missed calls (one JSON object per line),
// newest first.
function readMissed() {
	return L.resolveDefault(fs.read(MISSED), '').then(function(text) {
		var list = [];
		String(text || '').split('\n').forEach(function(line) {
			try {
				var m = line ? JSON.parse(line) : null;
				if (m && m.time)
					list.push(m);
			} catch (e) {}
		});
		return list.reverse();
	});
}

function missedTable(list) {
	if (!list.length)
		return E('p', {}, [ _('No missed calls.') ]);
	var rows = [
		E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, [ _('Time') ]),
			E('th', { 'class': 'th' }, [ _('Number') ]),
			E('th', { 'class': 'th' }, [ _('Why it was missed') ])
		])
	];
	list.slice(0, 50).forEach(function(m) {
		var t = new Date(Date.parse(m.time));
		rows.push(E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, [ isNaN(t) ? m.time : t.toLocaleString() ]),
			E('td', { 'class': 'td' }, [ m.from ? E('code', {}, [ m.from ]) : _('withheld') ]),
			E('td', { 'class': 'td' }, [ missedReasons[m.reason] || m.reason || '' ])
		]));
	});
	return E('table', { 'class': 'table' }, rows);
}

// readSMS: SMS to the SIM, newest first (mudi-volte sms --json): the ones
// the modem received and the ones that came over IMS.
function readSMS() {
	return L.resolveDefault(run(CLI, [ 'sms', '--json' ]).then(function(out) {
		var list = JSON.parse(out);
		return Array.isArray(list) ? list : [];
	}), []);
}

function smsTable(list) {
	if (!list.length)
		return E('p', {}, [ _('No SMS.') ]);
	var rows = [
		E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th', 'width': '20%' }, [ _('Time') ]),
			E('th', { 'class': 'th', 'width': '20%' }, [ _('From') ]),
			E('th', { 'class': 'th' }, [ _('Message') ])
		])
	];
	list.forEach(function(m) {
		var t = new Date(Date.parse(m.time));
		rows.push(E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, [ isNaN(t) ? m.time : t.toLocaleString() ]),
			E('td', { 'class': 'td' }, [ m.from || '' ]),
			E('td', { 'class': 'td', 'style': 'white-space:pre-wrap;word-break:break-word' }, [ m.text || '' ])
		]));
	});
	return E('table', { 'class': 'table' }, rows);
}

function duration(from, to) {
	var s = Math.max(0, Math.floor((Date.parse(to) - Date.parse(from)) / 1000));
	if (isNaN(s))
		return '';
	if (s < 60)
		return _('%d s').format(s);
	if (s < 3600)
		return _('%d min').format(Math.floor(s / 60));
	if (s < 86400)
		return _('%d h %d min').format(Math.floor(s / 3600), Math.floor(s % 3600 / 60));
	return _('%d d %d h').format(Math.floor(s / 86400), Math.floor(s % 86400 / 3600));
}

function row(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '33%' }, [ label ]),
		E('td', { 'class': 'td left' }, Array.isArray(value) ? value : [ value ])
	]);
}

function statusTable(st, missed) {
	if (!st || !st.alive)
		return E('p', {}, [ E('strong', { 'style': 'color:#c00' }, [ _('The service is not running.') ]), ' ',
			_('It starts by itself after setup; the log below tells why it stopped.') ]);
	var state = st.registered
		? E('strong', { 'style': 'color:#080' }, [ _('Online, calls work') ])
		: E('strong', { 'style': 'color:#c60' }, [ _('Connecting: %s').format(phases[st.phase] || st.phase) ]);
	var rows = [
		row(_('Status'), [ state, ' ', E('small', {}, [ _('for %s').format(duration(st.since, st.updated_at)) ]) ]),
		row(_('Phone number'), st.number || '—'),
		row(_('Mobile network'), st.rat ? '%s, IMS %s'.format(st.rat, st.interface || '') : '—'),
		row(_('Phones connected'), (st.phones && st.phones.length) ? st.phones.join(', ') : _('none'))
	];
	if (missed && missed.length)
		rows.push(row(_('Missed calls'), E('strong', {}, [ String(missed.length) ])));
	if (st.restarts > 0)
		rows.push(row(_('Reconnects to the operator'), String(st.restarts)));
	if (st.crash_restarts > 0)
		rows.push(row(_('Restarts after a crash'), _('%d in a row').format(st.crash_restarts)));
	if (st.last_error)
		rows.push(row(_('Last error'), [ E('small', {}, [ st.last_error ]) ]));
	return E('table', { 'class': 'table' }, rows);
}

function phoneSection(user) {
	var found = null;
	uci.sections('mudi-volte', 'phone', function(s) {
		if (s.user === user)
			found = s['.name'];
	});
	return found;
}

function lanAddress() {
	var ip = uci.get('mudi-volte', 'main', 'listen') || uci.get('network', 'lan', 'ipaddr') || '192.168.8.1';
	return String(ip).split('/')[0];
}

// transportText says how a phone set up by hand reaches the router.
function transportText() {
	var port = uci.get('mudi-volte', 'main', 'port') || '5060';
	var tls = uci.get('mudi-volte', 'main', 'tls_port') || '5061';
	if (uci.get('mudi-volte', 'main', 'encryption') === '0')
		return _('UDP on port %s').format(port);
	if (uci.get('mudi-volte', 'main', 'plain') === '0')
		return _('TLS on port %s with SRTP media encryption (SIP without encryption is off)').format(tls);
	return _('TLS on port %s with SRTP media encryption, or UDP on port %s without encryption').format(tls, port);
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('mudi-volte'),
			L.resolveDefault(uci.load('network'), null),
			readState(),
			readMissed(),
			readSMS()
		]);
	},

	clearMissed: function() {
		var self = this;
		return run(CLI, [ 'missed', 'clear' ]).then(function() {
			self.missed = [];
			self.refreshMissed();
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [ e.message ]), 'error');
		});
	},

	renderMissed: function() {
		var list = this.missed || [];
		return E('div', {}, [
			missedTable(list),
			list.length ? E('div', { 'class': 'right' }, [
				E('button', { 'class': 'cbi-button cbi-button-remove', 'click': ui.createHandlerFn(this, 'clearMissed') }, [ _('Clear the list') ])
			]) : '',
			E('p', {}, [ E('small', {}, [ _('Incoming calls that no phone answered. Calls cannot reach the router while it has no 4G or is offline; such calls do not show up here.') ]) ])
		]);
	},

	refreshMissed: function() {
		if (this.missedNode)
			dom.content(this.missedNode, this.renderMissed());
		if (this.statusNode)
			dom.content(this.statusNode, statusTable(this.state, this.missed));
	},

	showPhone: function(user) {
		var self = this;
		var sec = phoneSection(user);
		var pass = sec ? uci.get('mudi-volte', sec, 'password') : '';
		return run(CLI, [ 'phone', 'url', user ]).then(function(url) {
			url = url.trim();
			return run(IMSD, [ 'qr', '-svg', url ]).then(function(svg) {
				return [ url, svg ];
			});
		}).catch(function() {
			return [ '', '' ];
		}).then(function(r) {
			var url = r[0], svg = r[1];
			var body = [
				E('ol', { 'style': 'list-style:decimal;padding-left:1.5em;margin-left:0' }, [
					E('li', {}, [ _('Connect the phone to this router\'s Wi-Fi (not the guest network).') ]),
					E('li', {}, [ _('Install Linphone: free on Google Play and the App Store.') ]),
					E('li', {}, [ _('In Linphone choose "Scan QR code" (in the assistant at first start, or under remote provisioning / "Fetch remote configuration") and scan this code. Linphone sets up the account by itself.') ])
				])
			];
			if (url) {
				body.push(E('div', { 'style': 'text-align:center;margin:1em 0' }, [
					E('div', { 'style': 'display:inline-block;width:256px;height:256px' }, svg)
				]));
				body.push(E('p', {}, [ _('The same link, to type in instead: '), E('code', { 'style': 'word-break:break-all' }, [ url ]) ]));
				body.push(E('p', {}, [ E('small', {}, [ _('The link works only on this router\'s network. Do not share it: it signs a phone in.') ]) ]));
			}
			body.push(E('p', {}, [ _('By hand, in any SIP app:') ]));
			body.push(E('table', { 'class': 'table' }, [
				row(_('Username'), E('code', {}, [ user ])),
				row(_('Password'), E('code', {}, [ pass || '—' ])),
				row(_('Domain'), E('code', {}, [ lanAddress() ])),
				row(_('Transport'), transportText())
			]));
			var ext = sec ? uci.get('mudi-volte', sec, 'ext') : '';
			body.push(E('p', {}, [ ext
				? _('Other phones call and message this one by the name "%s" or the short number %s.').format(user, ext)
				: _('Other phones call and message this one by the name "%s".').format(user) ]));
			body.push(E('p', {}, [ E('small', {}, [ _('Call or message 600 to check the phone without the mobile network: you hear yourself, a message comes back. On Android let Linphone run without battery restrictions, or calls ring late. On an iPhone, calls ring while Linphone is in the background only with a push account (the linphone.org login in the settings); messages arrive while Linphone is open.') ]) ]));
			body.push(E('div', { 'style': 'display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end;margin-top:1em' }, [
				url ? E('button', { 'class': 'cbi-button cbi-button-action', 'click': ui.createHandlerFn(self, 'screenPhone', user) }, [ _('Show on the router\'s display') ]) : '',
				E('button', { 'class': 'cbi-button', 'click': ui.hideModal }, [ _('Close') ])
			]));
			ui.showModal(_('Connect the phone "%s"').format(user), body);
		});
	},

	// The same QR code on the router's own display (90 s, then auto-closes).
	screenPhone: function(user) {
		return run(CLI, [ 'phone', 'screen', user ]).then(function(out) {
			ui.addNotification(null, E('p', {}, [ String(out || '').trim() || _('Shown on the router\'s display.') ]), 'info');
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [ _('Could not show the code on the display: %s').format(e.message || e) ]), 'error');
		});
	},

	addPhone: function(input) {
		var name = (input.value || '').trim();
		if (!/^[A-Za-z0-9._-]{1,32}$/.test(name)) {
			ui.addNotification(null, E('p', {}, [ _('Phone name: up to 32 letters, digits, dots, dashes or underscores.') ]), 'warning');
			return Promise.resolve();
		}
		var self = this;
		return run(CLI, [ 'phone', 'add', name ]).then(function() {
			uci.unload('mudi-volte');
			return uci.load('mudi-volte');
		}).then(function() {
			input.value = '';
			self.refreshPhones();
			return self.showPhone(name);
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [ e.message ]), 'error');
		});
	},

	delPhone: function(user) {
		if (!confirm(_('Remove the phone "%s"? It can no longer sign in.').format(user)))
			return Promise.resolve();
		var self = this;
		return run(CLI, [ 'phone', 'del', user ]).then(function() {
			uci.unload('mudi-volte');
			return uci.load('mudi-volte');
		}).then(function() {
			self.refreshPhones();
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [ e.message ]), 'error');
		});
	},

	renderPhones: function() {
		var self = this, online = (this.state && this.state.phones) || [];
		var secure = (this.state && this.state.phones_tls) || [];
		var rows = [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, [ _('Phone') ]),
				E('th', { 'class': 'th' }, [ _('Short number') ]),
				E('th', { 'class': 'th' }, [ _('Connected') ]),
				E('th', { 'class': 'th cbi-section-actions' }, [])
			])
		];
		uci.sections('mudi-volte', 'phone', function(s) {
			if (!s.user)
				return;
			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, [ s.user ]),
				E('td', { 'class': 'td' }, [ s.ext || '—' ]),
				E('td', { 'class': 'td' }, [ secure.indexOf(s.user) >= 0 ? _('yes, encrypted') : online.indexOf(s.user) >= 0 ? _('yes') : _('no') ]),
				E('td', { 'class': 'td cbi-section-actions' }, [
					E('div', { 'style': 'gap:6px;justify-content:flex-end' }, [
						E('button', { 'class': 'cbi-button cbi-button-action', 'click': ui.createHandlerFn(self, 'showPhone', s.user) }, [ _('Connect / QR code') ]),
						E('button', { 'class': 'cbi-button cbi-button-remove', 'click': ui.createHandlerFn(self, 'delPhone', s.user) }, [ _('Remove') ])
					])
				])
			]));
		});
		var input = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': _('e.g. pixel'), 'maxlength': 32,
			'style': 'flex:1 1 10em;min-width:0' });
		return E('div', {}, [
			E('table', { 'class': 'table' }, rows),
			E('div', { 'class': 'cbi-section-create', 'style': 'display:flex;max-width:30em;margin-top:.5em' }, [
				input,
				E('button', { 'class': 'cbi-button cbi-button-add', 'style': 'flex:0 0 auto', 'click': ui.createHandlerFn(this, 'addPhone', input) }, [ _('Add phone') ])
			]),
			E('p', {}, [ E('small', {}, [ _('An incoming call rings all connected phones; the first to answer gets it. Phones call and message each other by name or short number, for free and without the SIM; during such a call callers to the SIM hear busy. Adding or removing a phone restarts the service: calls are offline for about 10 seconds.') ]) ])
		]);
	},

	refreshPhones: function() {
		if (this.phonesNode)
			dom.content(this.phonesNode, this.renderPhones());
	},

	startSetup: function() {
		var self = this, msg = _('The modem\'s own VoLTE gets switched off and the router restarts once: Wi-Fi and the internet are down for 2-3 minutes. Continue?');
		if (!confirm(msg))
			return Promise.resolve();
		return run(CLI, [ 'setup', '--detach' ]).then(function() {
			self.watchJob(_('Setting up'), {
				running: _('Switching the modem. If the router restarts, reconnect to its Wi-Fi in 2-3 minutes and open this page again.'),
				restarting: _('The router restarts now: reconnect to its Wi-Fi in 2-3 minutes and open this page again.'),
				failed: _('Setup failed: %s')
			});
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [ e.message ]), 'error');
		});
	},

	giveBack: function() {
		var self = this;
		if (!confirm(_('Give VoLTE back to the modem and restart the router? Calls through this router stop until you run the setup again.')))
			return Promise.resolve();
		return run(CLI, [ 'modem', 'builtin', '--detach' ]).then(function() {
			self.watchJob(_('Giving VoLTE back'), {
				running: _('Giving VoLTE back to the modem. Once the modem has taken its settings, the router restarts.'),
				restarting: _('The router restarts with the modem\'s own VoLTE. Reconnect in 2-3 minutes.'),
				failed: _('VoLTE is not given back to the modem: %s')
			});
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [ e.message ]), 'error');
		});
	},

	// watchJob shows the background run of setup or of the restore until it
	// fails, the router restarts or it is done. The router restarts only once
	// the modem has taken every value; a refusal ends the run with its reason,
	// and the router keeps running.
	watchJob: function(title, texts) {
		var note = E('p', { 'class': 'spinning' }, [ texts.running ]);
		var pre = E('pre', { 'style': 'max-height:15em;overflow:auto' }, [ '' ]);
		ui.showModal(title, [ note, pre ]);
		var step = function() {
			return Promise.all([
				L.resolveDefault(fs.read(SETUP_LOG), ''),
				L.resolveDefault(fs.read(SETUP_STATE), '')
			]).then(function(r) {
				var log = r[0] || '', state = jobState(r[1]);
				dom.content(pre, [ log ]);
				if (state === 'running')
					return;
				poll.remove(step);
				if (state === 'restarting') {
					dom.content(note, [ texts.restarting ]);
				} else if (state === 0) {
					ui.hideModal();
					location.reload();
				} else {
					ui.showModal(title, [
						E('div', { 'class': 'alert-message error' }, [ texts.failed.format(jobError(log, state)) ]),
						pre,
						E('div', { 'class': 'right' }, [
							E('button', { 'class': 'cbi-button', 'click': ui.hideModal }, [ _('Close') ])
						])
					]);
				}
			});
		};
		poll.add(step, 3);
	},

	showLog: function(pre) {
		return run(CLI, [ 'logs' ]).then(function(log) {
			dom.content(pre, [ log || _('The log is empty.') ]);
			pre.scrollTop = pre.scrollHeight;
		}).catch(function(e) {
			dom.content(pre, [ e.message ]);
		});
	},

	// addFooter: LuCI puts the Save & Apply bar at the end of the page; here it
	// goes right under the settings it saves.
	addFooter: function() {
		var footer = this.super('addFooter', []);
		var anchor = this.settingsNode;
		if (anchor && anchor.parentNode) {
			anchor.parentNode.insertBefore(footer, anchor.nextSibling);
			return E([]);
		}
		return footer;
	},

	render: function(data) {
		var self = this, enabled = uci.get('mudi-volte', 'main', 'enabled') === '1';
		this.state = data[2];
		this.missed = data[3] || [];
		this.sms = data[4] || [];

		var m = new form.Map('mudi-volte', null, null);
		var s = m.section(form.NamedSection, 'main', 'voip', _('Settings'),
			_('Saving the settings restarts the service: calls are offline for about 10 seconds.'));
		var o = s.option(form.ListValue, 'incoming', _('Who may call'));
		o.value('all', _('Everyone'));
		o.value('allow', _('Only the numbers below; others are declined'));
		o.default = 'all';
		o = s.option(form.DynamicList, 'allow', _('Allowed callers'), _('Full numbers with the country code, e.g. +447700900123.'));
		o.depends('incoming', 'allow');
		o.validate = function(id, v) {
			return (v === '' || /^\+?[0-9 ]{3,20}$/.test(v)) ? true : _('A phone number, e.g. +447700900123');
		};
		o = s.option(form.Value, 'dial', _('Outgoing calls and SMS'), _('* allows any number; or prefixes separated by spaces, e.g. "+44 +33".'));
		o.placeholder = '*';
		o.validate = function(id, v) {
			return (v === '' || /^(\*|(\+?[0-9]+)( +\+?[0-9]+)*)$/.test(v.trim())) ? true : _('* or prefixes such as +44 +33');
		};
		o = s.option(form.Value, 'country', _('Country code'), _('For numbers dialled with a leading 0, e.g. 44 for the UK. Setup fills it in from the SIM.'));
		o.datatype = 'and(uinteger,maxlength(4))';
		o = s.option(form.Value, 'ring_sec', _('Ring time, seconds'), _('How long the phones ring before the caller is declined.'));
		o.datatype = 'range(10,120)';
		o.placeholder = '45';
		o = s.option(form.Flag, 'sms', _('SMS on the phones'), _('New SMS go to every phone as messages (the chat in Linphone), and a message from a phone to a number goes out as an SMS. Off: SMS stay on the router.'));
		o.default = '1';
		o.rmempty = false;
		o = s.option(form.Flag, 'encryption', _('Encrypted calls'), _('SIP over TLS and SRTP audio for phones set up by QR code. A phone set up before calls without encryption until you scan its code again.'));
		o.default = '1';
		o.rmempty = false;
		o = s.option(form.Flag, 'plain', _('SIP without encryption'), _('UDP and TCP next to TLS, for phones set up by hand or before encryption came. Off: TLS only, every phone is set up by QR code, and nothing a phone signs can be read off the Wi-Fi.'));
		o.default = '1';
		o.rmempty = false;
		o.depends('encryption', '1');
		o = s.option(form.Value, 'push_login', _('Push notifications: linphone.org login'), _('iOS stops Linphone in the background, and Android may stop it too (battery savers, some phone makers). Then only a push from Linphone\'s makers wakes it for a call. The router asks their server (subscribe.linphone.org) to send it, signed with a free linphone.org account, and only when the phone has no connection; only the phone\'s push token and a random call ID leave the router. Empty: no pushes, an iPhone gets calls only while Linphone is open.'));
		o.placeholder = _('e.g. myname, without @sip.linphone.org');
		o.rmempty = true;
		o.validate = function(id, v) {
			return (v === '' || /^[A-Za-z0-9._+-]{1,64}$/.test(v)) ? true : _('The name of the linphone.org account, without @sip.linphone.org');
		};
		o = s.option(form.Value, 'push_password', _('linphone.org password'));
		o.password = true;
		o.rmempty = true;
		o.depends({ push_login: '', '!reverse': true });

		var statusNode = E('div', {}, [ statusTable(this.state, this.missed) ]);
		this.statusNode = statusNode;
		this.missedNode = E('div', {}, [ this.renderMissed() ]);
		var smsNode = E('div', {}, [ smsTable(this.sms) ]);
		this.phonesNode = E('div', {}, [ this.renderPhones() ]);
		var logPre = E('pre', { 'style': 'max-height:25em;overflow:auto;font-size:12px;white-space:pre-wrap;margin-top:.6em' }, [ _('Press "Show log".') ]);

		var head = [
			E('h2', {}, [ _('Calls & SMS') ]),
			E('div', { 'class': 'cbi-map-descr' }, [ _('Calls to and from the SIM in this router, on phones connected to its Wi-Fi (Linphone or another SIP app).') ])
		];

		if (!enabled) {
			return E([], head.concat([
				E('div', { 'class': 'cbi-section' }, [
					E('h3', {}, [ _('Set up') ]),
					E('p', {}, [ _('Setup checks the router, the modem and the SIM, creates a phone account and switches the modem to its "External VoLTE Stack" mode with voice over IMS only, so that calls to the SIM reach this router and the network never moves them to 3G. The router restarts once (2-3 minutes without Wi-Fi and internet). The SIM\'s operator must offer VoLTE on it.') ]),
					E('button', { 'class': 'cbi-button cbi-button-apply', 'click': ui.createHandlerFn(this, 'startSetup') }, [ _('Set up and restart the router') ])
				])
			]));
		}

		poll.add(function() {
			return Promise.all([ readState(), readMissed() ]).then(function(r) {
				var st = r[0];
				var phonesChanged = JSON.stringify((st && st.phones) || []) !== JSON.stringify((self.state && self.state.phones) || []);
				var missedChanged = JSON.stringify(r[1]) !== JSON.stringify(self.missed);
				self.state = st;
				self.missed = r[1];
				dom.content(statusNode, statusTable(st, self.missed));
				if (missedChanged)
					self.refreshMissed();
				if (phonesChanged)
					self.refreshPhones();
			});
		}, 5);

		poll.add(function() {
			return readSMS().then(function(list) {
				if (JSON.stringify(list) === JSON.stringify(self.sms))
					return;
				self.sms = list;
				dom.content(smsNode, smsTable(list));
			});
		}, 30);

		return m.render().then(function(mapNode) {
			self.settingsNode = mapNode;
			return E([], head.concat([
				E('div', { 'class': 'cbi-section' }, [ E('h3', {}, [ _('Status') ]), statusNode ]),
				E('div', { 'class': 'cbi-section' }, [ E('h3', {}, [ _('Missed calls') ]), self.missedNode ]),
				E('div', { 'class': 'cbi-section' }, [
					E('h3', {}, [ _('SMS') ]),
					smsNode,
					E('p', {}, [ E('small', {}, [ _('Messages to the SIM, newest first; with "SMS on the phones" on, new ones also go to every phone as messages. The operator delivers most of them to the modem, and the SMS page of the GL admin panel keeps them: delete them there.') ]) ])
				]),
				E('div', { 'class': 'cbi-section' }, [ E('h3', {}, [ _('Phones') ]), self.phonesNode ]),
				mapNode,
				E('div', { 'class': 'cbi-section' }, [
					E('h3', {}, [ _('Service log') ]),
					E('button', { 'class': 'cbi-button', 'click': ui.createHandlerFn(self, 'showLog', logPre) }, [ _('Show log') ]),
					logPre
				]),
				E('div', { 'class': 'cbi-section' }, [
					E('h3', {}, [ _('Give VoLTE back to the modem') ]),
					E('p', {}, [ _('Restores the modem settings saved during setup and restarts the router. Calls then go to the modem\'s own VoLTE again, and this page offers the setup.') ]),
					E('button', { 'class': 'cbi-button cbi-button-reset', 'click': ui.createHandlerFn(self, 'giveBack') }, [ _('Restore and restart') ])
				])
			]));
		});
	}
});
