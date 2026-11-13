/*
 * dsi_stub: a stand-in for the firmware's libdsi_netctrl.so, for the tests
 * of mudi-dsi-helper and of the daemon that runs it (src/imsd).
 *
 * It shares no declaration with the helper, on purpose. Its functions take
 * their arguments the way the firmware's library does (docs/PROTOCOLS.md,
 * section 2.2) and read the call parameter by its offsets, so a helper that
 * lays the structure out differently fails here, not on a router.
 *
 * Like the library it reports events from a thread of its own, may have no
 * handle to give for a while after dsi_init, notices a handle released with
 * its call still up, and registers an exit handler that must never run. And
 * like the library it refuses a call parameter it has no use for: the
 * firmware's tool never looks at that result, a helper has to get it right.
 *
 * DSI_STUB_LOG names a file that gets one line per call and per event.
 * DSI_STUB_MODE is a comma-separated list of what should go differently:
 *
 *   refuse         the network refuses the call: NO_NET, never IS_CONN
 *   refuse_ip=N    it refuses a call of IP version N (10 is IPv4v6) only
 *   silent         the call gets no reply at all
 *   drop           the network ends the call a moment after IS_CONN
 *   extra          other events around IS_CONN
 *   chatter        an address event every 50 ms once the call is up
 *   stranger       an event with somebody else's user data comes first
 *   noise          print to stdout and stderr, as a library might, from the
 *                  moment it is loaded
 *   slow_load=MS   loading the library takes MS milliseconds
 *   not_ready=N    no handle for the first N requests
 *   never_ready    no handle at all
 *   fail_subs, fail_init, fail_start, fail_stop
 *                  that function fails
 *   fail_param=N   setting parameter N fails
 *   silent_stop    the stop is accepted, but NO_NET never comes
 *   slow_stop=MS   send the stop's NO_NET after MS milliseconds (default: 30)
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum {
	PARAM_UMTS_PROFILE_IDX = 1,
	PARAM_TECH_PREF = 9,
	PARAM_IP_VERSION = 11,

	EVT_IS_CONN = 1,
	EVT_NO_NET = 2,
	EVT_PHYSLINK_UP = 4,
	EVT_RECONFIGURED = 5,
	EVT_NEWADDR = 8,
};

typedef void (*event_cb)(void *hndl, void *user_data, int evt, void *payload);

static struct {
	event_cb cb;
	void *user_data;
	int requests;  /* for a handle */
	int taken;     /* the handle is out */
	int ip_version; /* of the call, as set */
	atomic_int up; /* its call is up, or coming up */
	int chatter;
} call;

static char handle_storage[64]; /* the handle is its address */
static int stranger;            /* somebody else's user data */

#define HANDLE ((void *)handle_storage)

/* note appends one line to the log. */
static void note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void note(const char *fmt, ...)
{
	const char *path = getenv("DSI_STUB_LOG");
	char line[160];
	va_list ap;
	int fd, n;

	if (path == NULL)
		return;
	va_start(ap, fmt);
	n = vsnprintf(line, sizeof line - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof line - 2)
		n = (int)sizeof line - 2;
	line[n++] = '\n';
	fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0)
		return;
	if (write(fd, line, (size_t)n) < 0) {
		/* the test notices the missing line */
	}
	close(fd);
}

/*
 * mode_arg finds name in DSI_STUB_MODE. It returns NULL when it is not
 * there, and what follows "name=" (or an empty string) when it is.
 */
static const char *mode_arg(const char *name)
{
	const char *p = getenv("DSI_STUB_MODE");
	size_t len = strlen(name);

	while (p != NULL && *p != '\0') {
		if (strncmp(p, name, len) == 0) {
			if (p[len] == '\0' || p[len] == ',')
				return "";
			if (p[len] == '=')
				return p + len + 1;
		}
		p = strchr(p, ',');
		if (p != NULL)
			p++;
	}
	return NULL;
}

static int mode(const char *name)
{
	return mode_arg(name) != NULL;
}

static int mode_number(const char *name, int otherwise)
{
	const char *arg = mode_arg(name);

	return arg != NULL && *arg != '\0' ? atoi(arg) : otherwise;
}

static void nap(int ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };

	while (nanosleep(&ts, &ts) != 0) {
	}
}

static void babble(const char *what)
{
	char line[96];
	int n;

	if (!mode("noise"))
		return;
	printf("dsi_stub: %s on stdout, buffered\n", what);
	fflush(stdout);
	n = snprintf(line, sizeof line, "dsi_stub: %s on stdout, written\n", what);
	if (write(STDOUT_FILENO, line, (size_t)n) < 0) {
	}
	fprintf(stderr, "dsi_stub: %s on stderr\n", what);
}

/* A script is the events one call into the stub leads to, in order. */
struct script {
	int steps;
	struct {
		int delay_ms;
		int evt;
		void *user_data; /* NULL: the caller's own */
	} step[8];
};

static void then(struct script *s, int delay_ms, int evt, void *user_data)
{
	s->step[s->steps].delay_ms = delay_ms;
	s->step[s->steps].evt = evt;
	s->step[s->steps].user_data = user_data;
	s->steps++;
}

static void deliver(int evt, void *user_data)
{
	if (user_data == NULL) {
		note("event %d", evt);
		if (evt == EVT_NO_NET)
			call.up = 0;
		user_data = call.user_data;
	} else {
		note("event %d for a stranger", evt);
	}
	babble("an event");
	call.cb(HANDLE, user_data, evt, NULL);
}

static void *run_script(void *arg)
{
	struct script *s = arg;
	int i, ended = 0;

	for (i = 0; i < s->steps; i++) {
		nap(s->step[i].delay_ms);
		deliver(s->step[i].evt, s->step[i].user_data);
		if (s->step[i].evt == EVT_NO_NET && s->step[i].user_data == NULL)
			ended = 1;
	}
	free(s);
	while (!ended && call.chatter && call.up) {
		nap(50);
		if (call.up)
			deliver(EVT_NEWADDR, NULL);
	}
	return NULL;
}

static void play(struct script *s)
{
	struct script *copy;
	pthread_t thread;

	if (s->steps == 0)
		return;
	copy = malloc(sizeof *copy);
	if (copy == NULL)
		abort();
	*copy = *s;
	if (pthread_create(&thread, NULL, run_script, copy) != 0)
		abort();
	pthread_detach(thread);
}

/* Loading the library runs code already, its own and that of what it needs. */
__attribute__((constructor)) static void on_load(void)
{
	int ms = mode_number("slow_load", 0);

	babble("loading");
	if (ms > 0) {
		note("loading");
		nap(ms);
	}
}

/*
 * The library starts threads of its own in dsi_init. They take the signal
 * mask of the thread that called it, and so decide where a signal lands.
 */
static void *init_thread(void *arg)
{
	sigset_t set;

	(void)arg;
	pthread_sigmask(SIG_SETMASK, NULL, &set);
	note("thread term=%d int=%d hup=%d pipe=%d", sigismember(&set, SIGTERM),
	     sigismember(&set, SIGINT), sigismember(&set, SIGHUP), sigismember(&set, SIGPIPE));
	return NULL;
}

static void at_exit(void)
{
	note("exit handler");
}

static const char *whose(void *hndl)
{
	return hndl == HANDLE ? "" : " with a foreign handle";
}

int dsi_set_modem_subs_id(int subs_id);
int dsi_init(int mode);
void *dsi_get_data_srvc_hndl(event_cb cb, void *user_data);
int dsi_set_data_call_param(void *hndl, int identifier, void *info);
int dsi_start_data_call(void *hndl);
int dsi_stop_data_call(void *hndl);
void dsi_rel_data_srvc_hndl(void *hndl);

int dsi_set_modem_subs_id(int subs_id)
{
	note("subs %d", subs_id);
	return mode("fail_subs") ? -1 : 0;
}

int dsi_init(int init_mode)
{
	pthread_t thread;

	note("init %d", init_mode);
	babble("dsi_init");
	if (mode("fail_init"))
		return -1;
	atexit(at_exit);
	if (pthread_create(&thread, NULL, init_thread, NULL) != 0)
		abort();
	pthread_join(thread, NULL);
	return 0;
}

void *dsi_get_data_srvc_hndl(event_cb cb, void *user_data)
{
	call.requests++;
	if (mode("never_ready") || call.requests <= mode_number("not_ready", 0)) {
		note("handle refused");
		return NULL;
	}
	if (call.taken) {
		note("handle asked for twice");
		return NULL;
	}
	call.cb = cb;
	call.user_data = user_data;
	call.taken = 1;
	note("handle");
	return HANDLE;
}

/*
 * accepted tells whether the firmware's library takes this value for this
 * parameter, for the parameters whose code in the library was read; it is
 * no for any other parameter, until somebody reads that one too.
 */
static int accepted(int identifier, int32_t num_val)
{
	switch (identifier) {
	case PARAM_UMTS_PROFILE_IDX:
		return 1; /* any number: its low byte is what gets used */
	case PARAM_TECH_PREF:
		/*
		 * One of six technology bits. Not 0: the tool's menu has
		 * "AUTOMATIC" set that, and the library refuses it.
		 */
		return num_val == 1 || num_val == 2 || num_val == 4 || num_val == 8 ||
			num_val == 16 || num_val == 32;
	case PARAM_IP_VERSION:
		return num_val == 4 || num_val == 6 || num_val == 10 || num_val == 12;
	default:
		return 0;
	}
}

int dsi_set_data_call_param(void *hndl, int identifier, void *info)
{
	uint64_t buf_val;
	int32_t num_val;
	int ok;

	if (info == NULL) {
		note("param %d without a value%s refused", identifier, whose(hndl));
		return -1;
	}
	/* The value is 16 bytes: a pointer, then a number at offset 8. */
	memcpy(&buf_val, info, sizeof buf_val);
	memcpy(&num_val, (const char *)info + 8, sizeof num_val);
	ok = hndl == HANDLE && accepted(identifier, num_val) &&
		mode_number("fail_param", -1) != identifier;
	note("param %d num=%d buf=%s%s%s", identifier, (int)num_val, buf_val == 0 ? "null" : "set",
	     whose(hndl), ok ? "" : " refused");
	if (ok && identifier == PARAM_IP_VERSION)
		call.ip_version = num_val;
	return ok ? 0 : -1;
}

int dsi_start_data_call(void *hndl)
{
	struct script s = { 0 };
	int refused = mode("refuse") || mode_number("refuse_ip", -1) == call.ip_version;

	note("start%s", whose(hndl));
	if (mode("fail_start"))
		return -1;
	call.up = 1;
	call.chatter = mode("chatter");
	if (mode("silent"))
		return 0;
	if (mode("stranger"))
		then(&s, 10, EVT_IS_CONN, &stranger);
	if (mode("extra"))
		then(&s, 10, EVT_PHYSLINK_UP, NULL);
	then(&s, 30, refused ? EVT_NO_NET : EVT_IS_CONN, NULL);
	if (mode("extra")) {
		then(&s, 10, EVT_NEWADDR, NULL);
		then(&s, 10, EVT_RECONFIGURED, NULL);
	}
	if (mode("drop"))
		then(&s, 100, EVT_NO_NET, NULL);
	play(&s);
	return 0;
}

int dsi_stop_data_call(void *hndl)
{
	struct script s = { 0 };

	note("stop%s", whose(hndl));
	if (mode("fail_stop"))
		return -1;
	if (!mode("silent_stop"))
		then(&s, mode_number("slow_stop", 30), EVT_NO_NET, NULL);
	play(&s);
	return 0;
}

void dsi_rel_data_srvc_hndl(void *hndl)
{
	note("release%s%s", call.up ? " of a call that is up" : "", whose(hndl));
	call.up = 0;
	call.taken = 0;
}
