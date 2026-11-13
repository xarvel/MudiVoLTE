/*
 * mudi-dsi-helper: one data call through the firmware's DSI library.
 *
 * The IMS PDN has to come up through the modem's own data stack, so that
 * netmgrd configures the rmnet interface the daemon then talks over. The
 * firmware has a library for that, libdsi_netctrl.so, and no headers; its
 * only client on the router is the interactive test tool dsi_netctrl_test.
 * This helper makes the calls that tool makes for "create call, AUTOMATIC,
 * IP family, profile N, net up", those that take effect, with the same
 * arguments in the same order (docs/PROTOCOLS.md, section 2.2), and reports
 * what happens as JSON lines.
 * mudi-imsd starts it, reads the events and stops it; which interface the
 * call got, which addresses, and when to try again stay the daemon's
 * business.
 *
 * usage: mudi-dsi-helper SUBSCRIPTION PROFILE FAMILY
 *        mudi-dsi-helper check
 *
 *   SUBSCRIPTION  1 or 2: the modem subscription that places the call;
 *                 0: whichever is the default for data
 *   PROFILE       number of the modem profile (the CID of the APN), 1 to 255
 *   FAMILY        ipv4v6 or ipv4
 *
 * "check" loads the library and looks up the functions the helper calls,
 * without calling any of them: exit status 0 when they are all there. A
 * library that takes longer than CHECK_TIMEOUT_S to load counts as one that
 * cannot be loaded.
 *
 * Events, one JSON object per line on stdout:
 *
 *   {"v":1,"event":"library"}
 *       the library loads and has the functions: the answer to "check",
 *       and for a call the first event, before the helper calls into it
 *   {"v":1,"event":"ready","pid":N,"subscription":N,"profile":N,
 *    "family":"ipv4v6","tries":N}
 *       the call is set up; it starts now
 *   {"v":1,"event":"net_up"}
 *       the data call is connected
 *   {"v":1,"event":"stopping","signal":N}
 *       the helper was asked to stop and stops the call now: by signal N,
 *       or by the end of its stdin when N is 0. A net_down that follows is
 *       the end of this stop, not the network's doing
 *   {"v":1,"event":"net_down"}
 *       the data call ended, or the network refused it
 *   {"v":1,"event":"dsi_event","code":N}
 *       any other event of the library, by its number
 *   {"v":1,"event":"error","stage":"NAME","code":N}
 *       a step failed. NAME is the library function that failed, or
 *       library_load, library_symbol for a library the helper cannot use,
 *       or setup for a failure of its own
 *   {"v":1,"event":"exiting","code":N}
 *       the last line; N is the exit status
 *
 * Exit status: 0 stopped on request ("check": the library can be used),
 * 1 a step failed, 2 usage, 3 the network ended the call.
 *
 * To stop the helper send SIGTERM (or SIGINT, SIGHUP), or close its stdin:
 * it stops the call, waits for the modem to confirm, releases the handle and
 * exits. A daemon that dies closes the stdin of its helper, so the call does
 * not outlive the daemon. Whatever the libraries print goes to stderr.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>

#ifndef MUDI_DSI_LIBRARY
#define MUDI_DSI_LIBRARY "/usr/lib/libdsi_netctrl.so"
#endif

#define PROTOCOL_VERSION 1

/* Milliseconds; the tests build with shorter ones. */
#ifndef HANDLE_RETRY_MS
#define HANDLE_RETRY_MS 200 /* between two requests for a handle */
#endif
#ifndef HANDLE_TIMEOUT_MS
#define HANDLE_TIMEOUT_MS 15000 /* how long the library may stay not ready */
#endif
#ifndef STOP_WAIT_MS
#define STOP_WAIT_MS 2000 /* how long the modem may take to confirm a stop */
#endif
/* Seconds: how long "check" waits for the library to load. */
#ifndef CHECK_TIMEOUT_S
#define CHECK_TIMEOUT_S 10
#endif

#define TEXT(x) #x
#define NUMBER_TEXT(x) TEXT(x)

enum {
	EXIT_STOPPED = 0,
	EXIT_FAILED = 1,
	EXIT_USAGE = 2,
	EXIT_NET_DOWN = 3,
};

/*
 * The library's interface, as far as the helper uses it. Names and values
 * are those of Qualcomm's dsi_netctrl.h; every one was checked against the
 * code of dsi_netctrl_test and of the library. The library has no version to
 * ask for: like any program built against that header, the helper is bound
 * to it by the names of the functions and looks at what each call returns.
 */
typedef void *dsi_hndl_t;

typedef void (*dsi_net_ev_cb)(dsi_hndl_t hndl, void *user_data, int evt, void *payload);

typedef struct {
	char *buf_val; /* not read for the parameters set here */
	int num_val;
} dsi_call_param_value_t;

_Static_assert(sizeof(dsi_call_param_value_t) == 16, "dsi_call_param_value_t is 16 bytes");
_Static_assert(offsetof(dsi_call_param_value_t, num_val) == 8, "num_val is at offset 8");

enum {
	DSI_MODE_GENERAL = 0,

	DSI_CALL_INFO_UMTS_PROFILE_IDX = 1,
	DSI_CALL_INFO_IP_VERSION = 11,

	DSI_IP_VERSION_4 = 4,
	DSI_IP_VERSION_4_6 = 10,

	DSI_EVT_NET_IS_CONN = 1,
	DSI_EVT_NET_NO_NET = 2,
};

struct dsi_api {
	int (*set_modem_subs_id)(int subs_id);
	int (*init)(int mode);
	dsi_hndl_t (*get_data_srvc_hndl)(dsi_net_ev_cb cb, void *user_data);
	int (*set_data_call_param)(dsi_hndl_t hndl, int identifier, dsi_call_param_value_t *info);
	int (*start_data_call)(dsi_hndl_t hndl);
	int (*stop_data_call)(dsi_hndl_t hndl);
	void (*rel_data_srvc_hndl)(dsi_hndl_t hndl);
};

static const struct {
	const char *name;
	size_t slot;
} dsi_symbols[] = {
	{ "dsi_set_modem_subs_id", offsetof(struct dsi_api, set_modem_subs_id) },
	{ "dsi_init", offsetof(struct dsi_api, init) },
	{ "dsi_get_data_srvc_hndl", offsetof(struct dsi_api, get_data_srvc_hndl) },
	{ "dsi_set_data_call_param", offsetof(struct dsi_api, set_data_call_param) },
	{ "dsi_start_data_call", offsetof(struct dsi_api, start_data_call) },
	{ "dsi_stop_data_call", offsetof(struct dsi_api, stop_data_call) },
	{ "dsi_rel_data_srvc_hndl", offsetof(struct dsi_api, rel_data_srvc_hndl) },
};

_Static_assert(sizeof(void *) == sizeof(void (*)(void)), "dlsym results fit a function pointer");

struct options {
	int subscription;
	int profile;
	int family; /* DSI_IP_VERSION_* */
	const char *family_name;
};

static int event_fd = -1;         /* the JSON lines go here */
static int signal_fd = -1;        /* SIGTERM, SIGINT, SIGHUP arrive here */
static int event_pipe[2] = { -1, -1 }; /* DSI events, from the library's thread */
static int stdin_watched = 1;
static int stop_requested;
static int stop_signal; /* the signal that asked for the stop; 0: none did */
static int cookie; /* its address marks the events of this helper's call */

static void complain(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void leave(int status) __attribute__((noreturn));

/*
 * write_line writes a whole line to a pipe the daemon reads: the events, or
 * stderr. A reader that went away must not kill the helper before it has
 * stopped the call, so SIGPIPE is held back for this write alone; the
 * library's threads keep the default.
 */
static int write_line(int fd, const char *line, size_t len)
{
	sigset_t pipe_set, saved;
	int broken = 0;

	sigemptyset(&pipe_set);
	sigaddset(&pipe_set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &pipe_set, &saved);
	while (len > 0) {
		ssize_t n = write(fd, line, len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			broken = 1;
			if (errno == EPIPE) {
				const struct timespec now = { 0, 0 };

				while (sigtimedwait(&pipe_set, NULL, &now) < 0 && errno == EINTR) {
				}
			}
			break;
		}
		line += n;
		len -= (size_t)n;
	}
	pthread_sigmask(SIG_SETMASK, &saved, NULL);
	return !broken;
}

/*
 * hush points stdout and stderr at /dev/null once nobody reads them: the
 * daemon is gone. What a thread of the library prints from here on must not
 * end the helper half way through the stop.
 */
static void hush(void)
{
	int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		return;
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	if (fd > STDERR_FILENO)
		close(fd);
}

/* complain writes one line for a person to stderr. */
static void complain(const char *fmt, ...)
{
	char line[512];
	va_list ap;
	int n, m;

	n = snprintf(line, sizeof line, "mudi-dsi-helper: ");
	va_start(ap, fmt);
	m = vsnprintf(line + n, sizeof line - (size_t)n - 1, fmt, ap);
	va_end(ap);
	if (m < 0)
		m = 0;
	n += m;
	if (n > (int)sizeof line - 2)
		n = (int)sizeof line - 2;
	line[n++] = '\n';
	if (!write_line(STDERR_FILENO, line, (size_t)n))
		hush(); /* nowhere left to say so */
}

/*
 * emit writes one event. The arguments are fixed names and numbers only, so
 * there is nothing to escape.
 */
static void emit(const char *fmt, ...)
{
	char line[320];
	va_list ap;
	int n, m;

	if (event_fd < 0)
		return;
	n = snprintf(line, sizeof line, "{\"v\":%d,\"event\":", PROTOCOL_VERSION);
	va_start(ap, fmt);
	m = vsnprintf(line + n, sizeof line - (size_t)n, fmt, ap);
	va_end(ap);
	if (m < 0 || n + m > (int)sizeof line - 3) {
		complain("an event does not fit its line");
		return;
	}
	n += m;
	line[n++] = '}';
	line[n++] = '\n';
	if (!write_line(event_fd, line, (size_t)n)) {
		/* Nobody reads the events any more: the daemon is gone. */
		event_fd = -1;
		if (!stop_requested)
			complain("the event channel is closed: stopping");
		stop_requested = 1;
	}
}

static void emit_error(const char *stage, int code)
{
	emit("\"error\",\"stage\":\"%s\",\"code\":%d", stage, code);
}

/*
 * leave ends the process without running exit handlers. The library
 * registers one that takes its state apart under locks its threads may hold;
 * the firmware's own tool never runs it either, it is ended by a signal. The
 * kernel closes the QMI sockets, and the modem drops what the handle held.
 */
static void leave(int status)
{
	emit("\"exiting\",\"code\":%d", status);
	_exit(status);
}

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * load_library loads the library and looks up the functions the helper
 * calls. It emits the error itself when the library cannot be used.
 */
static int load_library(struct dsi_api *api)
{
	void *lib, *sym;
	size_t i;
	int ok = 1;

	/* RTLD_GLOBAL: as when the tool links against the library. */
	lib = dlopen(MUDI_DSI_LIBRARY, RTLD_NOW | RTLD_GLOBAL);
	if (lib == NULL) {
		const char *why = dlerror();

		complain("%s", why != NULL ? why : MUDI_DSI_LIBRARY ": cannot be loaded");
		emit_error("library_load", 0);
		return 0;
	}
	for (i = 0; i < sizeof dsi_symbols / sizeof dsi_symbols[0]; i++) {
		sym = dlsym(lib, dsi_symbols[i].name);
		if (sym == NULL) {
			complain("%s has no %s", MUDI_DSI_LIBRARY, dsi_symbols[i].name);
			ok = 0;
			continue;
		}
		memcpy((char *)api + dsi_symbols[i].slot, &sym, sizeof sym);
	}
	if (!ok)
		emit_error("library_symbol", 0);
	return ok;
}

/*
 * check_too_slow ends a "check" whose library does not load in time: a
 * constructor of it waits for something that is not there. The loader may be
 * half way through its work, so only what is safe in a signal handler.
 */
static void check_too_slow(int sig)
{
	static const char said[] = "mudi-dsi-helper: " MUDI_DSI_LIBRARY " did not load within "
		NUMBER_TEXT(CHECK_TIMEOUT_S) " s\n";
	static const char events[] =
		"{\"v\":" NUMBER_TEXT(PROTOCOL_VERSION) ",\"event\":\"error\",\"stage\":\"library_load\",\"code\":0}\n"
		"{\"v\":" NUMBER_TEXT(PROTOCOL_VERSION) ",\"event\":\"exiting\",\"code\":1}\n";

	_Static_assert(EXIT_FAILED == 1, "the exit status in the events above");
	(void)sig;
	if (write(STDERR_FILENO, said, sizeof said - 1) < 0) {
		/* nowhere left to say so */
	}
	if (event_fd >= 0 && write(event_fd, events, sizeof events - 1) < 0) {
		/* nobody reads them */
	}
	_exit(EXIT_FAILED);
}

/*
 * on_dsi_event runs on a thread of the library. It only queues the number of
 * the event for the main loop: nothing here may call into the library.
 */
static void on_dsi_event(dsi_hndl_t hndl, void *user_data, int evt, void *payload)
{
	int saved = errno;
	ssize_t n;

	(void)hndl;
	(void)payload;
	if (user_data == &cookie) {
		do
			n = write(event_pipe[1], &evt, sizeof evt);
		while (n < 0 && errno == EINTR);
	}
	errno = saved;
}

/* next_event takes one queued DSI event; 0 when there is none. */
static int next_event(int *evt)
{
	ssize_t n;

	do
		n = read(event_pipe[0], evt, sizeof *evt);
	while (n < 0 && errno == EINTR);
	return n == (ssize_t)sizeof *evt;
}

static void take_signal(void)
{
	struct signalfd_siginfo info;
	ssize_t n;

	do
		n = read(signal_fd, &info, sizeof info);
	while (n < 0 && errno == EINTR);
	if (n != (ssize_t)sizeof info)
		return;
	complain("signal %d: stopping", (int)info.ssi_signo);
	stop_requested = 1;
	stop_signal = (int)info.ssi_signo;
}

static void take_stdin(short revents)
{
	char buf[256];
	ssize_t n;

	if (revents & POLLNVAL) {
		stdin_watched = 0; /* started without a stdin */
		return;
	}
	n = read(STDIN_FILENO, buf, sizeof buf);
	if (n > 0 || (n < 0 && (errno == EINTR || errno == EAGAIN)))
		return; /* input means nothing; only the end of it does */
	if (n < 0) {
		stdin_watched = 0;
		return;
	}
	complain("stdin is closed: stopping");
	stop_requested = 1;
}

/*
 * idle sleeps for up to timeout_ms (-1: no limit). It returns early when a
 * stop is asked for and, with_events, when a DSI event is queued. Once a
 * stop is asked for it no longer looks: the end of stdin stays readable.
 */
static void idle(int timeout_ms, int with_events)
{
	struct pollfd fds[3];
	int n = 0, sig = -1, in = -1;

	if (with_events) {
		fds[n].fd = event_pipe[0];
		fds[n].events = POLLIN;
		fds[n++].revents = 0;
	}
	if (!stop_requested) {
		sig = n;
		fds[n].fd = signal_fd;
		fds[n].events = POLLIN;
		fds[n++].revents = 0;
		if (stdin_watched) {
			in = n;
			fds[n].fd = STDIN_FILENO;
			fds[n].events = POLLIN;
			fds[n++].revents = 0;
		}
	}
	if (poll(fds, (nfds_t)n, timeout_ms) <= 0)
		return;
	if (sig >= 0 && fds[sig].revents != 0)
		take_signal();
	if (in >= 0 && fds[in].revents != 0 && !stop_requested)
		take_stdin(fds[in].revents);
}

/*
 * setup_output keeps the event lines apart from what the library prints. It
 * has to be in place before the library loads.
 */
static int setup_output(void)
{
	int fd, err;

	/*
	 * A standard descriptor the helper was started without becomes
	 * /dev/null, or the next file it opens would take its place. A stdin
	 * that was never there is not a request to stop.
	 */
	for (fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
		if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF)
			continue;
		if (open("/dev/null", O_RDWR) != fd)
			return 0;
		if (fd == STDIN_FILENO)
			stdin_watched = 0;
	}

	/*
	 * The events get a descriptor of their own, and stdout becomes
	 * stderr: a library that prints cannot break the event lines.
	 */
	event_fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
	if (event_fd < 0) {
		complain("stdout: %s", strerror(errno));
		return 0;
	}
	if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
		err = errno;
		complain("stderr: %s", strerror(err));
		emit_error("setup", err);
		return 0;
	}
	return 1;
}

/*
 * setup_call prepares what a call needs, also before the library loads: the
 * signal mask the library's threads inherit, the descriptor a stop request
 * arrives on, and the pipe the library's events are queued in.
 */
static int setup_call(void)
{
	sigset_t set;
	int err;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	/*
	 * Blocked in every thread and read from a descriptor: a stop request
	 * then never interrupts a call into the library half way.
	 */
	err = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (err != 0) {
		complain("cannot block signals: %s", strerror(err));
		emit_error("setup", err);
		return 0;
	}
	signal_fd = signalfd(-1, &set, SFD_CLOEXEC | SFD_NONBLOCK);
	if (signal_fd < 0) {
		err = errno;
		complain("signalfd: %s", strerror(err));
		emit_error("setup", err);
		return 0;
	}
	if (pipe2(event_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
		err = errno;
		complain("pipe: %s", strerror(err));
		emit_error("setup", err);
		return 0;
	}
	return 1;
}

/* number parses a decimal in [min, max]; 0 when s is anything else. */
static int number(const char *s, int min, int max, int *out)
{
	long v = 0;
	const char *p;

	if (*s == '\0' || strlen(s) > 4)
		return 0;
	for (p = s; *p != '\0'; p++) {
		if (*p < '0' || *p > '9')
			return 0;
		v = v * 10 + (*p - '0');
	}
	if (v < min || v > max)
		return 0;
	*out = (int)v;
	return 1;
}

static int parse_args(int argc, char **argv, struct options *opt)
{
	if (argc != 4)
		return 0;
	if (!number(argv[1], 0, 2, &opt->subscription))
		return 0;
	/* The library keeps the number in one byte and drops the rest of it. */
	if (!number(argv[2], 1, 255, &opt->profile))
		return 0;
	if (strcmp(argv[3], "ipv4v6") == 0)
		opt->family = DSI_IP_VERSION_4_6;
	else if (strcmp(argv[3], "ipv4") == 0)
		opt->family = DSI_IP_VERSION_4;
	else
		return 0;
	opt->family_name = argv[3];
	return 1;
}

static int set_param(const struct dsi_api *dsi, dsi_hndl_t handle, int identifier, int value)
{
	dsi_call_param_value_t info;
	int rc;

	memset(&info, 0, sizeof info);
	info.num_val = value;
	rc = dsi->set_data_call_param(handle, identifier, &info);
	if (rc != 0) {
		complain("dsi_set_data_call_param(%d, %d) = %d", identifier, value, rc);
		emit("\"error\",\"stage\":\"dsi_set_data_call_param\",\"code\":%d,\"param\":%d", rc, identifier);
	}
	return rc == 0;
}

/* report passes one DSI event on; 1 when it ends the call. */
static int report(int evt)
{
	switch (evt) {
	case DSI_EVT_NET_IS_CONN:
		emit("\"net_up\"");
		return 0;
	case DSI_EVT_NET_NO_NET:
		emit("\"net_down\"");
		return 1;
	default:
		emit("\"dsi_event\",\"code\":%d", evt);
		return 0;
	}
}

int main(int argc, char **argv)
{
	struct options opt;
	struct dsi_api dsi;
	dsi_hndl_t handle;
	int64_t deadline, left;
	int tries = 0, evt, rc;

	if (argc == 2 && strcmp(argv[1], "check") == 0) {
		/*
		 * The library is loaded and nothing in it called. There is no
		 * call to stop, so the stop signals are left as the helper
		 * found them (by default they end it); an alarm ends a load
		 * that does not finish (mudi-volte setup waits for this
		 * answer).
		 */
		struct sigaction too_slow;
		int loaded, err;

		if (!setup_output())
			leave(EXIT_FAILED);
		memset(&too_slow, 0, sizeof too_slow);
		too_slow.sa_handler = check_too_slow;
		sigemptyset(&too_slow.sa_mask);
		if (sigaction(SIGALRM, &too_slow, NULL) != 0) {
			err = errno;
			complain("sigaction: %s", strerror(err));
			emit_error("setup", err);
			leave(EXIT_FAILED);
		}
		alarm(CHECK_TIMEOUT_S);
		memset(&dsi, 0, sizeof dsi);
		loaded = load_library(&dsi);
		alarm(0);
		if (!loaded)
			leave(EXIT_FAILED);
		emit("\"library\"");
		leave(0);
	}
	if (!parse_args(argc, argv, &opt)) {
		complain("usage: mudi-dsi-helper SUBSCRIPTION PROFILE FAMILY | check");
		complain("  SUBSCRIPTION 0 (default), 1 or 2; PROFILE 1..255; FAMILY ipv4v6 or ipv4");
		return EXIT_USAGE;
	}
	if (!setup_output() || !setup_call())
		leave(EXIT_FAILED);
	memset(&dsi, 0, sizeof dsi);
	if (!load_library(&dsi))
		leave(EXIT_FAILED);
	/*
	 * What fails from here on fails on this router, not in the network,
	 * until "ready": the daemon tells the one from the other by this line.
	 */
	emit("\"library\"");

	/* From here on: the calls of dsi_netctrl_test, in its order. */
	if (opt.subscription != 0) {
		rc = dsi.set_modem_subs_id(opt.subscription);
		if (rc != 0) {
			emit_error("dsi_set_modem_subs_id", rc);
			leave(EXIT_FAILED);
		}
	}
	rc = dsi.init(DSI_MODE_GENERAL);
	if (rc != 0) {
		emit_error("dsi_init", rc);
		leave(EXIT_FAILED);
	}

	/*
	 * dsi_init returns before the library has heard from netmgrd, and has
	 * no handle to give until then (a person at the tool's menu never
	 * notices): ask until it has one.
	 */
	deadline = now_ms() + HANDLE_TIMEOUT_MS;
	for (;;) {
		tries++;
		handle = dsi.get_data_srvc_hndl(on_dsi_event, &cookie);
		if (handle != NULL || now_ms() >= deadline)
			break;
		idle(HANDLE_RETRY_MS, 0);
		if (stop_requested)
			leave(EXIT_STOPPED);
	}
	if (handle == NULL) {
		complain("no data service handle after %d requests: is netmgrd running?", tries);
		emit_error("dsi_get_data_srvc_hndl", 0);
		leave(EXIT_FAILED);
	}

	/*
	 * For "AUTOMATIC" the tool also sets a technology preference of 0
	 * here (parameter 9). The library refuses that value and changes
	 * nothing, and the tool does not look at the result: automatic is a
	 * preference nobody set. So the helper sets none.
	 */
	if (!set_param(&dsi, handle, DSI_CALL_INFO_IP_VERSION, opt.family) ||
	    !set_param(&dsi, handle, DSI_CALL_INFO_UMTS_PROFILE_IDX, opt.profile)) {
		dsi.rel_data_srvc_hndl(handle);
		leave(EXIT_FAILED);
	}

	idle(0, 0);
	if (stop_requested) {
		dsi.rel_data_srvc_hndl(handle);
		leave(EXIT_STOPPED);
	}
	emit("\"ready\",\"pid\":%ld,\"subscription\":%d,\"profile\":%d,\"family\":\"%s\",\"tries\":%d",
	     (long)getpid(), opt.subscription, opt.profile, opt.family_name, tries);
	if (stop_requested) {
		/* Nobody took that line: the daemon is gone, the call is for nobody. */
		dsi.rel_data_srvc_hndl(handle);
		leave(EXIT_STOPPED);
	}

	rc = dsi.start_data_call(handle);
	if (rc != 0) {
		emit_error("dsi_start_data_call", rc);
		dsi.rel_data_srvc_hndl(handle);
		leave(EXIT_FAILED);
	}

	while (!stop_requested) {
		idle(-1, 1);
		while (next_event(&evt)) {
			if (report(evt)) {
				/* The call is over and the handle idle: nothing to stop. */
				dsi.rel_data_srvc_hndl(handle);
				leave(EXIT_NET_DOWN);
			}
		}
	}

	/*
	 * Stop, then give the modem a moment to confirm before the handle
	 * goes: whoever dials next finds the PDN really down. Releasing a
	 * handle that is still up stops its call as well, so a modem that
	 * stays silent loses nothing. The daemon hears first who asked: the
	 * NO_NET of this stop is not the network's doing.
	 */
	emit("\"stopping\",\"signal\":%d", stop_signal);
	rc = dsi.stop_data_call(handle);
	if (rc != 0) {
		emit_error("dsi_stop_data_call", rc);
	} else {
		int down = 0;

		deadline = now_ms() + STOP_WAIT_MS;
		while (!down && (left = deadline - now_ms()) > 0) {
			idle((int)left, 1);
			while (!down && next_event(&evt))
				down = report(evt);
		}
		if (!down)
			complain("no NO_NET within %d ms of the stop", STOP_WAIT_MS);
	}
	dsi.rel_data_srvc_hndl(handle);
	leave(EXIT_STOPPED);
}
