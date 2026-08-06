/* sample program to parse the JSON log to populate syscall_opt structs that is utilized by the syscall replayer
*  Assisted By: Claude Sonnette
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cJSON.h"


#define MAX_PROCNAME 256
#define MAX_SYSCALLNAME 64
#define MAX_FILENAME 4096
#define MAX_IODIR 16
#define LINE_BUF (MAX_FILENAME + 512)
#define JSON_BUFFER_SIZE (MAX_FILENAME * 20)  // Large buffer for multi-line JSON objects

/*
* define the syscall_opt struct
*/

typedef struct {
	uint64_t timestamp_ns;
	double timestamp_ms;
	int32_t pid;
	char process_name[MAX_PROCNAME];
	int32_t syscall_nr;
	char syscall_name[MAX_SYSCALLNAME];
	int32_t fd;
	int64_t size;
	int64_t offset;
	char filename[MAX_FILENAME];
	int32_t open_flags_hex;
	char open_flags_str[MAX_FILENAME];
	char io_direction[MAX_IODIR];
	int32_t ret;
	int32_t error_code;
} syscall_opt;

/* implements the parser */
#define REQUIRE_STR(key, dst, dstsz)     \
    do { \
	cJSON *_n = cJSON_GetObjectItemCaseSensitive(root, key); \
	if (!cJSON_IsString(_n) || _n->valuestring == NULL) { \
	    fprintf(stderr, "Error: Missing or invalid '%s' field\n", key); \
	    cJSON_Delete(json); \
	    return -1; \
	} \
	strncpy(dst, _n->valuestring, (dstsz) - 1); \
	dst[(dstsz) - 1] = '\0'; \
    } while (0)

#define REQUIRE_INT(key, dst, ctype)     \
    do { \
	cJSON *_n = cJSON_GetObjectItemCaseSensitive(root, key); \
	if (!cJSON_IsNumber(_n)) { \
	    fprintf(stderr, "Error: Missing or invalid '%s' field\n", key); \
	    cJSON_Delete(json); \
	    return -1; \
	} \
	dst = (ctype)_n->valuedouble; \
    } while (0)

#define REQUIRE_DOUBLE(key, dst)     \
    do { \
	cJSON *_n = cJSON_GetObjectItemCaseSensitive(root, key); \
	if (!cJSON_IsNumber(_n)) { \
	    fprintf(stderr, "Error: Missing or invalid '%s' field\n", key); \
	    cJSON_Delete(json); \
	    return -1; \
	} \
	dst = _n->valuedouble; \
    } while (0)

#define OPTIONAL_STR(key, dst, dstsz, default_val)     \
    do { \
	cJSON *_n = cJSON_GetObjectItemCaseSensitive(root, key); \
	if (cJSON_IsString(_n) && _n->valuestring != NULL) { \
	    strncpy(dst, _n->valuestring, (dstsz) - 1); \
	    dst[(dstsz) - 1] = '\0'; \
	} else { \
	    strncpy(dst, default_val, (dstsz) - 1); \
	    dst[(dstsz) - 1] = '\0'; \
	} \
    } while (0)

/* Returns 0 on success , -1 on parse/validation error */
int callsys_from_json(const char *utf8_json, syscall_opt *opt)
{

   if (!utf8_json || !opt) return -1;

    cJSON *json = cJSON_Parse(utf8_json);
    if (!json) {
	const char *err = cJSON_GetErrorPtr();
	fprintf(stderr, "Error parsing JSON: %s\n", err ? err : "Unknown error");
	return -1;
    }

    cJSON *root = json;

    /* Special handling for timestamp_ns - can be number or string */
    cJSON *ts = cJSON_GetObjectItemCaseSensitive(root, "timestamp_ns");

    if (cJSON_IsNumber(ts)) {
	opt->timestamp_ns = (uint64_t)ts->valuedouble;
    } else if (cJSON_IsString(ts)) {
	opt->timestamp_ns = strtoull(ts->valuestring, NULL, 10);
    } /*else if (ts == NULL) {
	fprintf(stderr, "Error: Missing or invalid 'timestamp_ns' field\n");
	cJSON_Delete(json);
	return -1;
    } */

    /* Parse all other required fields using standard macros */
    REQUIRE_DOUBLE("timestamp_ms", opt->timestamp_ms);
    REQUIRE_INT("pid", opt->pid, int32_t);
    REQUIRE_STR("process_name", opt->process_name, MAX_PROCNAME);
    REQUIRE_INT("syscall_nr", opt->syscall_nr, int32_t);
    REQUIRE_STR("syscall_name", opt->syscall_name, MAX_SYSCALLNAME);
    REQUIRE_INT("fd", opt->fd, int32_t);
    REQUIRE_INT("size", opt->size, int64_t);
    REQUIRE_INT("offset", opt->offset, int64_t);
    OPTIONAL_STR("filename", opt->filename, MAX_FILENAME, "");
    REQUIRE_STR("io_direction", opt->io_direction, MAX_IODIR);
    REQUIRE_INT("open_flags_hex", opt->open_flags_hex, int32_t);
    OPTIONAL_STR("open_flags_str", opt->open_flags_str, MAX_FILENAME, "");
    REQUIRE_INT("ret", opt->ret, int32_t);
    REQUIRE_INT("error_code", opt->error_code, int32_t);

    cJSON_Delete(json);
    return 0;
}

#undef REQUIRE_STR
#undef REQUIRE_INT
#undef REQUIRE_DOUBLE
#undef OPTIONAL_STR

static void callsys_printf(const syscall_opt *s)
{
    printf("timestamp_ns: %llu\n",(unsigned long long) s->timestamp_ns);
    printf("timestamp_ms: %.3f\n", s->timestamp_ms);
    printf("pid: %d\n", s->pid);
    printf("process_name: %s\n", s->process_name);
    printf("syscall_nr: %d\n", s->syscall_nr);
    printf("syscall_name: %s\n", s->syscall_name);
    printf("fd: %d\n", s->fd);
    printf("size: %ld\n", s->size);
    printf("offset: %ld\n", s->offset);
    printf("filename: %s\n", s->filename[0] != '\0' ? s->filename : "(empty)");
    printf("io_direction: %s\n", s->io_direction);
    printf("open_flags_hex: 0x%x\n", s->open_flags_hex);
    printf("open_flags_str: %s\n", s->open_flags_str[0] != '\0' ? s->open_flags_str : "(empty)");
    printf("ret: %d\n", s->ret);
    printf("error_code: %d\n", s->error_code);

}

/* main */

int main(void)
{
	FILE *fp = fopen("syscall_events_fixed.json", "r");
	if (!fp) {
		fprintf(stderr, "Error opening file\n");
		return -1;
	}

	char line[LINE_BUF];
	char json_buffer[LINE_BUF * 15];  // Buffer to accumulate multi-line JSON
	int lineno = 0;
	int errors = 0;
	int brace_count = 0;  // Track opening/closing braces
	int in_object = 0;    // Flag to know if we're inside a JSON object

	while(fgets(line, sizeof(line), fp)) {
		++lineno;

		// Skip empty lines and whitespace-only lines
		if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0')
		   continue;

		// Count braces to detect complete JSON objects
		for (int i = 0; line[i] != '\0'; i++) {
			if (line[i] == '{') {
				brace_count++;
				in_object = 1;
			} else if (line[i] == '}') {
				brace_count--;
			}
		}

		// Accumulate lines into buffer
		if (in_object) {
			strncat(json_buffer, line, sizeof(json_buffer) - strlen(json_buffer) - 1);
		}

		// When braces balance (brace_count == 0), we have a complete JSON object
		if (in_object && brace_count == 0) {
			// Remove trailing newlines/carriage returns from buffer
			size_t len = strlen(json_buffer);
			while (len > 0 && (json_buffer[len - 1] == '\n' || json_buffer[len - 1] == '\r')) {
				json_buffer[--len] = '\0';
			}

			// Parse the complete JSON object
			syscall_opt *entry = calloc(1, sizeof(syscall_opt));
			if (!entry) {
				fprintf(stderr, "Error allocating memory for entry\n");
				json_buffer[0] = '\0';
				in_object = 0;
				continue;
			}

			printf("Parsing JSON object: %s\n", json_buffer);

			if (callsys_from_json(json_buffer, entry) == 0) {
				printf("Parsed successfully:\n");
				callsys_printf(entry);
			} else {
				fprintf(stderr, "Error parsing JSON object starting at line %d\n", lineno);
				errors++;
			}
			free(entry);

			// Reset for next object
			json_buffer[0] = '\0';
			in_object = 0;
		}
	}

	fclose(fp);
	if (errors > 0) {
		fprintf(stderr, "Finished with %d errors\n", errors);
	} else {
		printf("Finished successfully\n");
	}

	return 0;
}