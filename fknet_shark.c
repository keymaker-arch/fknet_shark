#include <glib.h>
#include <epan/epan.h>
#include <wsutil/cmdarg_err.h>
#include <ui/failure_message.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <wsutil/version_info.h>
#include <wiretap/wtap.h>
#include <epan/color_filters.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/column-info.h>
#include <epan/print.h>
#include <epan/epan_dissect.h>
#include <epan/disabled_protos.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>

#define TIMEOUT 20

static epan_t *epan;
static epan_dissect_t *edt;
static wtap_rec rec;
static frame_data fdlocal;
static char buf[0x10000];
static unsigned count;
static struct timespec watchdog_feed_time;
static char watchdog_enabled;

void print_hex_buf(char* _buf, int len) {
    for (int i = 0; i < len; i++) {
        fprintf(stderr, "%02x ", (unsigned char)_buf[i]);
    }
    fprintf(stderr, "\n");
}

void* watchdog_thr(void* arg) {
    struct timespec now;
    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (watchdog_enabled) {
            if (now.tv_sec - watchdog_feed_time.tv_sec > TIMEOUT) {
                fprintf(stderr, "[SHARK] Watchdog timeout, last packet:\n");
                print_hex_buf(buf, count);
                exit(-1);
            }
        }
        sleep(1);
    }
}

void watchdog_feed(void) {
    clock_gettime(CLOCK_MONOTONIC, &watchdog_feed_time);
}

static const nstime_t *
fuzzshark_get_frame_ts(struct packet_provider_data *prov _U_, uint32_t frame_num _U_)
{
	static nstime_t empty;

	return &empty;
}

static epan_t *
fuzzshark_epan_new(void)
{
	static const struct packet_provider_funcs funcs = {
		fuzzshark_get_frame_ts,
		NULL,
		NULL,
		NULL
	};

	return epan_new(NULL, &funcs);
}

void do_dissect(void) {
	memset(&rec, 0, sizeof(rec));
	rec.rec_type = REC_TYPE_PACKET;
	rec.rec_header.packet_header.caplen = count - sizeof(unsigned);
	rec.rec_header.packet_header.len = count - sizeof(unsigned);
	rec.rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;
	rec.presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
	frame_data_init(&fdlocal, 1, &rec, 0, 0);
    printf("run dissect\n");
	epan_dissect_run(edt, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, &rec, tvb_new_real_data(buf + sizeof(unsigned), count - sizeof(unsigned), count - sizeof(unsigned)), &fdlocal, NULL);
	frame_data_destroy(&fdlocal);
    printf("write pdml\n");
    write_pdml_proto_tree(NULL, edt, NULL, stdout, false);
	epan_dissect_reset(edt);
}

void handle_input(void) {
    unsigned packet_len=0;
    int read_ret;

    count = 0;

    read_ret = read(0, buf, sizeof(buf));
    if (read_ret < 4) {
        fprintf(stderr, "read STDIN failed, got: %d\n", read_ret);
        exit(-1);
    } else {
        count = read_ret;
    }

    packet_len = *(unsigned*)buf;

    if (packet_len + sizeof(unsigned) == count) {
        return;
    }

    // incomplete first read, read the remaining bytes
    while (count < packet_len + sizeof(unsigned)) {
        read_ret = read(0, buf + count, sizeof(buf) - count);
        // FIXME: set a timeout
        if (read_ret < 0) {
            continue;
        }
        count += read_ret;
    }

    if (count != packet_len + sizeof(unsigned)) {
        fprintf(stderr, "Invalid packet length, expect: %ld, got: %d\n", packet_len+sizeof(unsigned), count);
        exit(-1);
    }
}

int main(int argc, char** argv) {
    fd_set readfds;
    struct timeval tv;
    int flags;
    pthread_t thrs;

    // setvbuf(stdout, NULL);
    setvbuf(stderr, NULL, _IONBF, 0);

	ws_log_init("fuzzshark", vcmdarg_err);
	ws_log_parse_args(&argc, argv, vcmdarg_err, LOG_ARGS_NOEXIT);
	init_process_policies();

    wtap_init(false);

    epan_init(NULL, NULL, false);

	epan_load_settings();

    epan = fuzzshark_epan_new();
	edt = epan_dissect_new(epan, true, true);
    // edt->pi.fragmented = false;

    FD_ZERO(&readfds);
    FD_SET(0, &readfds);

    // set STDIN non-blocking
    flags = fcntl(0, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl get flag");
        exit(1);
    }
    flags |= O_NONBLOCK;
    if (fcntl(0, F_SETFL, flags) == -1) {
        perror("fcntl set flag");
        exit(1);
    }

    pthread_create(&thrs, NULL, watchdog_thr, NULL);

    while (1) {
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
        if (select(1, &readfds, NULL, NULL, &tv) == -1) {
            perror("select");
            exit(1);
        } else if (FD_ISSET(0, &readfds)) {
            watchdog_enabled = 1;
            watchdog_feed();
            handle_input();
            do_dissect();
            
            fprintf(stdout, "\n\n");

            fflush(stdout);
            watchdog_enabled = 0;
        } else {
            fprintf(stderr, "[SHARK] time out waiting for data from STDIN\n");
            exit(-1);
        }
    }

    return 0;
}