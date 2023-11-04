#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <limits.h>

#include "cov_inject.h"

static int g_debug;

#define dbg_print(fmt, args...)		do {	\
	if (g_debug)							\
		fprintf(stderr, fmt, ##args);		\
} while(0)

struct cmdline {
	int argc;
	char **argv;
};

struct cmdline *cmd_create(int argc, char **argv)
{
	struct cmdline *n = calloc(1, sizeof(struct cmdline));
	n->argc = argc;
	n->argv = calloc(argc + 1, sizeof(char *));

	int i;
	for (i = 0; i < argc; ++i) {
		n->argv[i] = strdup(argv[i]);
	}

	return n;
}

struct cmdline *cmd_dup(const struct cmdline *cmd)
{
	return cmd_create(cmd->argc, cmd->argv);
}

void cmd_replace(struct cmdline *cmd, int idx, const char *txt)
{
	assert(idx >= 0 && idx < cmd->argc);
	free(cmd->argv[idx]);
	cmd->argv[idx] = strdup(txt);
}

void cmd_remove(struct cmdline *cmd, const char *opt, int follow)
{
	int i = 1;

	while (i < cmd->argc) {
		if (strcmp(cmd->argv[i], opt) == 0) {
			char *rem1 = cmd->argv[i];
			char *rem2 = NULL;

			if (follow && i + 1 < cmd->argc) {
				rem2 = cmd->argv[i + 1];
				memmove(&cmd->argv[i], &cmd->argv[i + 2], (cmd->argc + 1 - (i + 2)) * sizeof(char *));
				cmd->argc -= 2;
			} else {
				memmove(&cmd->argv[i], &cmd->argv[i + 1], (cmd->argc + 1 - (i + 1)) * sizeof(char *));
				cmd->argc -= 1;
			}

			free(rem1);
			free(rem2);
			continue;
		}
		++i;
	}
}

static const char *cmd_get_output(struct cmdline *cmd, int *idx)
{
	int i;

	for (i = 1; i < cmd->argc; ++i) {
		if (strcmp(cmd->argv[i], "-o") == 0) {
			if (i + 1 < cmd->argc) {
				if (idx)
					*idx = i + 1;
				return cmd->argv[i + 1];
			}
		}
	}

	return NULL;
}

static const char *cmd_get_input(struct cmdline *cmd, int *idx)
{
	int i;

	for (i = 1; i < cmd->argc; ++i) {
		const char *f = cmd->argv[i];
		size_t len = strlen(f);

		if (len > 2 && strcmp(f + len - 2, ".c") == 0) {
			if (idx)
				*idx = i;
			return f;
		}
	}

	return NULL;
}

static int cmd_has_c_opt(struct cmdline *cmd, int *idx)
{
	int i;
	
	for (i = 1; i < cmd->argc; ++i) {
		if (strcmp(cmd->argv[i], "-c") == 0) {
			if (idx)
				*idx = i;
			return 1;
		}
	}
	return 0;
}

static void cmd_debug(const char *label, const struct cmdline *cmd)
{
	int i;

	dbg_print("%s [%d]: ", label, getpid());

	for (i = 0; i < cmd->argc; ++i) {
		dbg_print("%s ", cmd->argv[i]);
	}

	dbg_print("\n");
}

static int cmd_exec_gcc(struct cmdline *cmd)
{
	pid_t pid = fork();
	if (pid < 0)
		exit(1);

	if (pid == 0) {
		const char *gcc = getenv("ORIG_CC");
		if (!gcc)
			gcc = "gcc";

		cmd_replace(cmd, 0, gcc);

		cmd_debug("GCC", cmd);

		execvp(gcc, cmd->argv);
		perror("execvp");
		exit(1);
	} else {
		int status = 0;
		if (waitpid(pid, &status, 0) < 0) {
			perror("waitpid");
			exit(1);
		}

		if (status)
			exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	}

	return 0;
}

static const char *filename(const char *f)
{
	const char *p = strrchr(f, '/');
	if (p) {
		++p;
		return p;
	} else {
		return f;
	}
}

static void inject_coverage(const char *arg0, const char *file)
{
	pid_t pid = fork();
	if (pid < 0)
		exit(1);
	
	if (pid == 0) {
		exit(cov_inject(file));
	} else {
		int status = 0;
		if (waitpid(pid, &status, 0) < 0) {
			perror("waitpid");
			exit(1);
		}

		if (status)
			exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	}
}

int main(int argc, char **argv)
{
	struct cmdline *cmdline = cmd_create(argc, argv);

	g_debug = (getenv("COVDEBUG") && *getenv("COVDEBUG") == '1');
	if (g_debug) {
		cmd_debug("COVCC_START", cmdline);
	}

	int input_idx, output_idx, c_idx;
	const char *input = cmd_get_input(cmdline, &input_idx);
	const char *output = cmd_get_output(cmdline, &output_idx);
	int compile = cmd_has_c_opt(cmdline, &c_idx);

	if (input && output && compile) {
		struct cmdline *new_cmd = cmd_dup(cmdline);
		cmd_replace(new_cmd, c_idx, "-E");

		char new_output[PATH_MAX];
		snprintf(new_output, sizeof(new_output), "/tmp/%s.c", filename(output));

		cmd_replace(new_cmd, output_idx, new_output);
		cmd_exec_gcc(new_cmd);

		inject_coverage(argv[0], new_output);

		struct cmdline *cmd2 = cmd_dup(cmdline);
		cmd_replace(cmd2, input_idx, new_output);
		cmd_remove(cmd2, "-include", 1);
		cmd_exec_gcc(cmd2);
	} else {
		return cmd_exec_gcc(cmdline);
	}

	return 0;
}