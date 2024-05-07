#include <sys/resource.h>
#include <condition_variable>
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <cstring>
#include <queue>
#include <map>
#include <set>
#include <perfmon/pfmlib.h>
#include <perfmon/pfmlib_perf_event.h>
#include <err.h>
#include <signal.h>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <mutex>
#ifndef PEBS_H
#define PEBS_H

#define START 0

// #define PERF_PAGES 65
#define PERF_PAGES (1 + (1 << 6))

#ifndef SAMPLE_PERIOD
#define SAMPLE_PERIOD 200
#endif

#ifndef TIDNUM
#define TIDNUM 8
#endif

#define SAMPLECPU 30
#define _GNU_SOURCE

using namespace std;

struct perf_sample
{
	struct perf_event_header header;
	__u64 ip;		/* if PERF_SAMPLE_IP */
	__u32 pid, tid; /* if PERF_SAMPLE_TID */
	__u64 time;		/* if PERF_SAMPLE_TIME */
	__u64 addr;		/* if PERF_SAMPLE_ADDR */
					//__u64 phys_addr; /* if PERF_SAMPLE_PHYS_ADDR */
};

enum pbuftype
{
	L_D = 0,
	R_D = 1,
	L_W = 2,

	// WRITE,
	NPBUFTYPES
};

typedef struct CPU_TID
{
	int cpuid;
	int tid;
} CPU_TID;

#endif

// DEFINITION
CPU_TID cputid[TIDNUM];
__u64 event[4];

// exclusive cpus for QEMU thread and PEBS threads
// SAMPLECPU 33, defined in pebs.h

struct perf_event_mmap_page *perf_page[TIDNUM][NPBUFTYPES];
int pfd[TIDNUM][NPBUFTYPES];
char filename[64];
pthread_t sample_thread_t;
std::mutex mutex1;
std::condition_variable cv;

bool kernel_finished = true;
char buffer[40960];

FILE *fp;

long _perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	int ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

__u64 _get_read_attr()
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	int ret = pfm_get_perf_event_encoding("MEM_LOAD_L3_MISS_RETIRED.LOCAL_DRAM", 
										PFM_PLMH, &attr, NULL, NULL);
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "Cannot get encoding %s\n", pfm_strerror(ret));
		assert(ret == PFM_SUCCESS);
	}
	// printf("%d\n", ret);

	return attr.config;
}

__u64 _get_write_attr()
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	int ret = pfm_get_perf_event_encoding("MEM_INST_RETIRED.STLB_MISS_STORES",
										PFM_PLMH, &attr, NULL, NULL);
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "Cannot get encoding %s\n", pfm_strerror(ret));
		assert(ret == PFM_SUCCESS);
	}
	return attr.config;
}
 

__u64 _get_local_dram_read_attr(){

	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	// here we will change the evert name 
	int ret = pfm_get_perf_event_encoding("MEM_LOAD_L3_MISS_RETIRED.LOCAL_DRAM",
										PFM_PLMH, &attr, NULL, NULL);
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "Cannot get encoding %s\n", pfm_strerror(ret));
		assert(ret == PFM_SUCCESS);
	}

	return attr.config;
}


 __u64 _get_remote_dram_read_attr(){

	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	// here we will change the evert name 
	int ret = pfm_get_perf_event_encoding("MEM_LOAD_L3_MISS_RETIRED.REMOTE_DRAM",
										PFM_PLMH, &attr, NULL, NULL);
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "Cannot get encoding %s\n", pfm_strerror(ret));
		assert(ret == PFM_SUCCESS);
	}
		// printf("%d\n", ret);

	return attr.config;

}

__u64 _get_local_PM_read_attr(){

	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	// here we will change the evert name 
	int ret = pfm_get_perf_event_encoding("MEM_LOAD_RETIRED.LOCAL_PMM",
										PFM_PLMH, &attr, NULL, NULL);
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "Cannot get encoding %s\n", pfm_strerror(ret));
		assert(ret == PFM_SUCCESS);
	}
		// printf("%d\n", ret);
	return attr.config;
}


__u64 _get_remote_PM_read_attr(){
	
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	// here we will change the evert name 
	int ret = pfm_get_perf_event_encoding("MEM_LOAD_L3_MISS_RETIRED.REMOTE_PMM",
										PFM_PLMH, &attr, NULL, NULL);
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "Cannot get encoding %s\n", pfm_strerror(ret));
		assert(ret == PFM_SUCCESS);
	}
		// printf("%d\n", ret);
	return attr.config;

}

struct perf_event_mmap_page *_get_perf_page(int pfd)
{
	// for this config; they map 4KB * PERF_PAGES. ()
	size_t mmap_size = sysconf(_SC_PAGESIZE) * PERF_PAGES;
	// printf("mmap_size %ld\n", mmap_size);
	struct perf_event_mmap_page *p =
		reinterpret_cast<struct perf_event_mmap_page *>(mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
															 MAP_SHARED, pfd, 0));

	if (p == MAP_FAILED)
	{
		fprintf(stderr, "mmap for pfd(%d) failed!\n", pfd);
		assert(p != MAP_FAILED);
	}
	// printf("%d\n", ret);

	return p;
}

void perf_setup()
{
	// arrt1 - READ; attr2 - WRITE
	struct perf_event_attr attr[5];
	for (int i = 0; i < TIDNUM; ++i)
	{
		for (int j = START; j < NPBUFTYPES; j++)
		{
			memset(&attr[j], 0, sizeof(struct perf_event_attr));
			attr[j].type = PERF_TYPE_RAW;
			attr[j].size = sizeof(struct perf_event_attr);
			attr[j].config = event[j];
			attr[j].config1 = 0;
			attr[j].sample_period = SAMPLE_PERIOD;
			attr[j].sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_TIME;
			attr[j].disabled = 0;
			attr[j].exclude_kernel = 1;
			attr[j].exclude_hv = 1;
			attr[j].exclude_idle = 1;
			attr[j].exclude_callchain_kernel = 1;
			attr[j].exclude_callchain_user = 1;
			attr[j].precise_ip = 1;
			//
			pfd[i][j] = _perf_event_open(attr + j, cputid[i].tid ,/*-1*/ cputid[i].cpuid, -1, 0);
			if (pfd[i][j] == -1)
			{
				if (errno == ESRCH)
					fprintf(stderr, "No such process(nid=%d)\n", cputid[i].tid);
				assert(pfd[i][j] != -1);
			}
			perf_page[i][j] = _get_perf_page(pfd[i][j]);
			assert(perf_page[i][j] != NULL);
		}
	} // end of setup events for each TID
}

void signal_handler(int signum)
{
	if (signum == SIGUSR1)
	{
		std::unique_lock<std::mutex> lk(mutex1);
		kernel_finished = true;
		printf("signal\n");
		lk.unlock();
		cv.notify_one();
	}
	// Perform necessary actions upon signal reception
	// Resume execution or handle received data from the kernel module
}

void init(const char *filename)
{
	// cputid should be already initialized inside main() ahead
	__u64 ts = time(NULL);
	// snprintf(filename, sizeof(filename), "profiling_%lu", ts);
	fp = fopen(filename, "w");
	if (!fp)
	{
		fprintf(stderr, "fopen file[%s] error!\n", filename);
		assert(fp != NULL);
	}
	for (int i = 0; i < TIDNUM; ++i)
	{
		for (int j = 0; j < NPBUFTYPES; ++j)
		{
			perf_page[i][j] = NULL;
			pfd[i][j] = -1;
		}
	}

	int ret = pfm_initialize();
	if (ret != PFM_SUCCESS)
	{
		fprintf(stderr, "Cannot initialize library: %s\n",
				pfm_strerror(ret));
		assert(ret == PFM_SUCCESS);
	}

	// event[0] = _get_local_dram_read_attr();
	if(0>= START) event[0] = _get_read_attr();
	if (1>=START) event[1] = _get_remote_dram_read_attr();
	// if(2>= START) event[2] = _get_local_PM_read_attr();
	// if(3>= START) event[3] = _get_remote_PM_read_attr();
	if(4>= START) event[2] = _get_write_attr();
	// printf("%lu\n", event[0]);
	// printf("%lu\n", event[1]);
	// printf("%lu\n", event[2]);
	// printf("%lu\n", event[3]);
	// printf("%lu\n", event[4]);
	perf_setup();
}

void *sample_thread_func(void *arg)
{
	int cancel_type = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	if (cancel_type)
		fprintf(stderr, "thread cancel_type setting failed!\n");
	assert(cancel_type == 0);

	// set affinity
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(SAMPLECPU, &cpuset);
	pthread_t thread = pthread_self();
	int affinity_ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	assert(affinity_ret == 0); // if (affinity_ret)	fprintf(stderr, "pthread_setaffinity_np failed!\n");

	// set the sychronization signal handler
	signal(SIGUSR1, signal_handler);

	int switch_on = 0;
	__u64 addr;

	while (true)
	{
		for (int index = 0; index < TIDNUM; ++index)
		{
			for (int i = START; i < NPBUFTYPES; ++i)
			{
				// printf("running\n");
				struct perf_event_mmap_page *p = perf_page[index][i];
				char *pbuf = (char *)p + p->data_offset;
				__sync_synchronize();
				// printf("sync\n");
				// printf("scan the buffer\n");
				if (p->data_head == p->data_tail)
				{
						// printf("continue\n");
					continue;
				}
				// printf("recording\n");
				// while (p->data_head != p->data_tail) {
				struct perf_event_header *ph =
					reinterpret_cast<struct perf_event_header *>(pbuf + (p->data_tail % p->data_size));
				assert(ph != NULL);
				struct perf_sample *ps;
				// printf("%d\n", ph->type);
				switch (ph->type)
				{
				case PERF_RECORD_SAMPLE:
					ps = (struct perf_sample *)ph;
					assert(ps != NULL);

					// Here should be a condition that we should start the analysis.
					if (ps->addr != 0)
					{
						fprintf(fp, "%llu %llu %d %d\n", (void *)(ps->addr), ps->time, index, i);
					}
					break;
				case PERF_RECORD_THROTTLE:
					printf("PERF_RECORD_THROTTL\n");
					break;
				case PERF_RECORD_UNTHROTTLE:
					break;
				default:
					break; // fprintf(stderr, "Unknown perf_sample type %u\n", ph->type);
				}		   // got the perf sample
				p->data_tail += ph->size;
				// } // extract all the events in the ring buffer
			} // end of loop NPBUFTYPES
		}	  // end of loop for each sampled thread

	} // Repeated Sampling
	return NULL;
}

void INThandler(int sig)
{
	signal(sig, SIG_IGN);
	int ret_cancel = pthread_cancel(sample_thread_t);
	if (ret_cancel)
		fprintf(stderr, "pthread_cancel failed!\n");
	assert(ret_cancel == 0);
	// Do cleaning
	for (int i = 0; i < TIDNUM; ++i)
	{
		for (int j = 0; j < NPBUFTYPES; ++j)
		{
			if (perf_page[i][j])
			{
				munmap(perf_page[i][j], sysconf(_SC_PAGESIZE) * PERF_PAGES);
				perf_page[i][j] = NULL;
			}
			if (pfd[i][j] != -1)
			{
				ioctl(pfd[i][j], PERF_EVENT_IOC_DISABLE, 0);
				close(pfd[i][j]);
				pfd[i][j] = -1;
			}
		}
	}
	// fclose(fp);
	// fp = NULL;
}

int main(int argc, char **argv)
{

	if (argc != 2)
	{
		printf("argv[1] is filename. argv[2] is the split \n");
	}

	printf("%d %d\n", SAMPLE_PERIOD, TIDNUM);

	for (int i = 0; i < TIDNUM; i++)
	{
		cputid[i].cpuid = i;
		cputid[i].tid = -1;
	}

	init(argv[1]);
	signal(SIGINT, INThandler);
	// lauch the sampling threads
	printf("lauch the sampling threads\n");

	int ret = pthread_create(&sample_thread_t, NULL, sample_thread_func, NULL);
	if (ret)
		fprintf(stderr, "pthread_create failed!\n");
	assert(ret == 0);

	std::system("mpirun -np 8 taskset -c 0-7 ./../gups/gups_vanilla 33 1000 2048");

	// Wait for sampling thread finish
	void *ret_thread;
	int join_ret = pthread_join(sample_thread_t, &ret_thread);
	if (join_ret)
		fprintf(stderr, "pthread_join failed!\n");
	assert(join_ret == 0);
	if (ret_thread != PTHREAD_CANCELED)
		fprintf(stderr, "pthread_cancel failed!\n");
	assert(ret_thread == PTHREAD_CANCELED);

	return 0;
}

