#define main nvme_uring_cmd_smoke_program_main
#include "../nvme_uring_cmd_smoke.c"
#undef main

#define CHECK(condition)                                                     \
	do {                                                                   \
		if (!(condition)) {                                               \
			fprintf(stderr, "CHECK failed at %s:%d: %s\n",             \
				__FILE__, __LINE__, #condition);                       \
			return 1;                                                  \
		}                                                              \
	} while (0)

static int read_exact(int fd, char *buffer, size_t length)
{
	size_t consumed = 0;

	while (consumed < length) {
		ssize_t ret = read(fd, buffer + consumed, length - consumed);

		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return -1;
		consumed += ret;
	}
	return 0;
}

static int test_fixed_address_semantics(void)
{
	const void *address = (void *)(uintptr_t)0x12345000;
	struct options opts = {};

	opts.fixed = true;
	CHECK(command_buffer_addr(&opts, address) == (uintptr_t)address);
	opts.hugepage = true;
	CHECK(command_buffer_addr(&opts, address) == (uintptr_t)address);
	opts.fixed = false;
	opts.hugepage = false;
	CHECK(command_buffer_addr(&opts, address) == (uintptr_t)address);
	opts.premap = true;
	CHECK(command_buffer_addr(&opts, address) == 0);
	return 0;
}

static int test_fifo_free_slot_scheduler(void)
{
	uint32_t storage[4];
	struct free_slot_queue queue;
	uint32_t slot;

	free_slot_queue_init(&queue, storage, 4);
	CHECK(!free_slot_queue_take(&queue, &slot) && slot == 0);
	CHECK(!free_slot_queue_take(&queue, &slot) && slot == 1);
	CHECK(!free_slot_queue_take(&queue, &slot) && slot == 2);
	CHECK(!free_slot_queue_release(&queue, 1));
	CHECK(!free_slot_queue_take(&queue, &slot) && slot == 3);
	CHECK(!free_slot_queue_take(&queue, &slot) && slot == 1);
	CHECK(free_slot_queue_take(&queue, &slot) == -EAGAIN);
	CHECK(!free_slot_queue_release(&queue, 0));
	CHECK(!free_slot_queue_release(&queue, 2));
	CHECK(!free_slot_queue_release(&queue, 3));
	CHECK(!free_slot_queue_release(&queue, 1));
	CHECK(queue.count == queue.capacity);
	CHECK(free_slot_queue_release(&queue, 0) == -EPROTO);
	return 0;
}

static int test_matrix_option_parse(void)
{
	char *argv[] = {
		"nvme_uring_cmd_smoke",
		"--buffer-len", "2097152",
		"--len", "131072",
		"--qd", "64",
		"--slots", "256",
		"--fixed",
		"--hugepage",
		NULL,
	};
	struct options opts = {
		.dev = DEFAULT_DEV,
		.count = DEFAULT_COUNT,
		.qd = DEFAULT_QD,
		.io_len = DEFAULT_IO_LEN,
		.lba_size = DEFAULT_LBA_SIZE,
		.cmds_per_obj = DEFAULT_CMDS_PER_OBJ,
		.trace_base = DEFAULT_TRACE_BASE,
		.ready_fd = -1,
		.start_fd = -1,
	};
	struct geometry geometry = {};

	optind = 1;
	CHECK(!parse_options(11, argv, &opts));
	CHECK(opts.fixed && opts.hugepage && !opts.premap);
	CHECK(opts.io_len == 131072);
	CHECK(opts.buffer_len == 2097152);
	CHECK(opts.qd == 64 && opts.slots == 256);
	CHECK(!strcmp(mode_name(&opts), "fixed-hugetlb"));
	CHECK(!validate_options(&opts, &geometry));
	CHECK(geometry.allocated_bytes == UINT64_C(536870912));
	return 0;
}

static int test_barrier_protocol(void)
{
	struct options opts = { .ready_fd = -1, .start_fd = -1 };
	struct barrier_state state = {};
	char events[sizeof("ready\nerror\n") - 1];
	int event_pipe[2], control_pipe[2];

	CHECK(!pipe(event_pipe));
	CHECK(!pipe(control_pipe));
	CHECK(write(control_pipe[1], "SF", 2) == 2);
	opts.ready_fd = event_pipe[1];
	opts.start_fd = control_pipe[0];
	CHECK(!measurement_begin(&opts, &state));
	CHECK(!measurement_finish(&opts, true, &state));
	CHECK(!read_exact(event_pipe[0], events, sizeof("ready\ndone\n") - 1));
	CHECK(!memcmp(events, "ready\ndone\n", sizeof("ready\ndone\n") - 1));
	CHECK(state.enabled && state.ready_emitted && state.start_acknowledged);
	CHECK(state.outcome_emitted && state.timed_loop_complete);
	CHECK(state.finish_acknowledged && barrier_protocol_complete(&state));
	CHECK(!close(event_pipe[0]));
	CHECK(!close(event_pipe[1]));
	CHECK(!close(control_pipe[0]));
	CHECK(!close(control_pipe[1]));

	CHECK(!pipe(event_pipe));
	CHECK(!pipe(control_pipe));
	CHECK(write(control_pipe[1], "X", 1) == 1);
	memset(&state, 0, sizeof(state));
	opts.ready_fd = event_pipe[1];
	opts.start_fd = control_pipe[0];
	CHECK(measurement_begin(&opts, &state) == -EPROTO);
	CHECK(!read_exact(event_pipe[0], events, sizeof(events)));
	CHECK(!memcmp(events, "ready\nerror\n", sizeof(events)));
	CHECK(state.ready_emitted && !state.start_acknowledged);
	CHECK(state.outcome_emitted && !barrier_protocol_complete(&state));
	CHECK(!close(event_pipe[0]));
	CHECK(!close(event_pipe[1]));
	CHECK(!close(control_pipe[0]));
	CHECK(!close(control_pipe[1]));

	CHECK(!pipe(event_pipe));
	CHECK(!pipe(control_pipe));
	CHECK(!close(control_pipe[1]));
	memset(&state, 0, sizeof(state));
	opts.ready_fd = event_pipe[1];
	opts.start_fd = control_pipe[0];
	CHECK(measurement_begin(&opts, &state) == -EPIPE);
	CHECK(!read_exact(event_pipe[0], events, sizeof(events)));
	CHECK(!memcmp(events, "ready\nerror\n", sizeof(events)));
	CHECK(state.ready_emitted && state.outcome_emitted);
	CHECK(!barrier_protocol_complete(&state));
	CHECK(!close(event_pipe[0]));
	CHECK(!close(event_pipe[1]));
	CHECK(!close(control_pipe[0]));
	return 0;
}

static int test_latency_summary(void)
{
	uint64_t samples[] = {
		LATENCY_DONE_BIT | 500,
		LATENCY_DONE_BIT | 100,
		LATENCY_DONE_BIT | 300,
		LATENCY_DONE_BIT | 200,
		LATENCY_DONE_BIT | 400,
	};
	struct latency_stats stats;

	CHECK(!calculate_latency_stats(samples, 5, &stats));
	CHECK(stats.samples == 5);
	CHECK(stats.mean_ns == 300);
	CHECK(stats.p50_ns == 300);
	CHECK(stats.p95_ns == 500);
	CHECK(stats.p99_ns == 500);
	CHECK(stats.max_ns == 500);
	return 0;
}

static int test_json_escape(void)
{
	char *rendered = NULL;
	size_t length = 0;
	FILE *stream = open_memstream(&rendered, &length);

	CHECK(stream != NULL);
	json_string(stream, "quote=\" slash=\\ newline=\n");
	CHECK(!fclose(stream));
	CHECK(!strcmp(rendered, "\"quote=\\\" slash=\\\\ newline=\\n\""));
	free(rendered);
	return 0;
}

static int test_normal_backing_proof(void)
{
	long page_size = sysconf(_SC_PAGESIZE);
	struct hugepage_meminfo meminfo;
	struct user_backing backing = {};
	struct geometry geometry = {};
	struct options opts = {
		.dev = DEFAULT_DEV,
		.count = 4,
		.qd = 1,
		.slots = 2,
		.io_len = DEFAULT_IO_LEN,
		.lba_size = DEFAULT_LBA_SIZE,
		.cmds_per_obj = DEFAULT_CMDS_PER_OBJ,
		.trace_base = DEFAULT_TRACE_BASE,
		.ready_fd = -1,
		.start_fd = -1,
	};
	int ret;

	CHECK(page_size > 0 && page_size <= UINT32_MAX);
	opts.buffer_len = page_size;
	CHECK(!validate_options(&opts, &geometry));
	CHECK(!read_hugepage_meminfo(&meminfo));
	ret = allocate_user_backing(&opts, &geometry, &meminfo, &backing);
	CHECK(!ret);
	ret = collect_backing_proof(&opts, &meminfo, &backing);
	CHECK(!ret);
	CHECK(backing.proof.madv_nohugepage);
	CHECK(backing.proof.resident_pages == backing.proof.total_pages);
	CHECK(backing.proof.aligned_slots == opts.slots);
	CHECK(backing.proof.smaps.vmflag_nh);
	CHECK(!backing.proof.smaps.vmflag_ht);
	CHECK(!backing.proof.smaps.anon_huge_kb);
	CHECK(backing.proof.smaps.kernel_page_kb == (uint64_t)page_size / 1024);
	CHECK(backing.proof.smaps.mmu_page_kb == (uint64_t)page_size / 1024);
	free(backing.iovecs);
	CHECK(!munmap(backing.base, backing.map_len));
	return 0;
}

static int emit_test_json(void)
{
	unsigned char touched = 1;
	struct options opts = {
		.dev = "test-\"device",
		.count = 1,
		.qd = 1,
		.slots = 1,
		.io_len = 4096,
		.buffer_len = 4096,
		.lba_size = 512,
		.cmds_per_obj = 1,
		.trace_base = 7,
		.ready_fd = -1,
		.start_fd = -1,
	};
	struct geometry geometry = {
		.blocks_per_io = 8,
		.allocated_bytes = 4096,
		.requested_bytes = 4096,
		.last_lba_exclusive = 8,
		.trace_last = 7,
	};
	struct hugepage_meminfo meminfo = {
		.valid = true,
		.page_size_kb = 2048,
	};
	struct user_backing backing = {
		.map_len = 4096,
		.proof = {
			.system_page_bytes = 4096,
			.required_alignment_bytes = 4096,
			.total_pages = 1,
			.resident_pages = 1,
			.aligned_slots = 1,
			.madv_nohugepage = true,
			.smaps = {
				.found = true,
				.covers_mapping = true,
				.vmflag_nh = true,
				.kernel_page_kb = 4,
				.mmu_page_kb = 4,
			},
		},
	};
	struct run_result result = {
		.submitted = 1,
		.completed = 1,
		.elapsed_ns = 1000,
		.touched_slots = 1,
		.expected_touched_slots = 1,
		.touched_bitmap = &touched,
		.touched_bitmap_bytes = 1,
		.slot_validation_passed = true,
		.latency = {
			.samples = 1,
			.mean_ns = 900,
			.p50_ns = 900,
			.p95_ns = 900,
			.p99_ns = 900,
			.max_ns = 900,
		},
	};
	struct barrier_state barrier = {};

	return print_run_json(stdout, &opts, &geometry, &backing, &meminfo,
			      &meminfo, &result, &barrier, 1) ? 1 : 0;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--emit-json"))
		return emit_test_json();
	CHECK(argc == 1);
	CHECK(!test_fixed_address_semantics());
	CHECK(!test_fifo_free_slot_scheduler());
	CHECK(!test_matrix_option_parse());
	CHECK(!test_barrier_protocol());
	CHECK(!test_latency_summary());
	CHECK(!test_json_escape());
	CHECK(!test_normal_backing_proof());
	puts("nvme_uring_cmd_smoke unit tests: PASS");
	return 0;
}
