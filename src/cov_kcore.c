#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>

#include "cov_kcore.h"

struct kcore_sect {
	unsigned long vaddr;
	unsigned long vaddr_end;
	unsigned long offset;
};

struct kcore_access {
	struct kcore_sect *sects;
	int nr_sect;
	int fd;
};

void kcore_access_destroy(struct kcore_access *acc)
{
	if (!acc)
		return;

	free(acc->sects);
	free(acc);
}

struct kcore_access *kcore_access_create(const char *file)
{
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;
	int i;

	int fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s failed: %s\n", file, strerror(errno));
		return NULL;
	}

	if (read(fd, &ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
		fprintf(stderr, "read %s failed: %s\n", file, strerror(errno));
		goto close_ret;
	}
	
	if (lseek(fd, ehdr.e_phoff, SEEK_SET) == -1) {
		fprintf(stderr, "lseek %s failed: %s\n", file, strerror(errno));
		goto close_ret;
	}

	struct kcore_access *acc = calloc(1, sizeof(struct kcore_access));
	acc->sects = calloc(ehdr.e_phnum, sizeof(struct kcore_sect));
	acc->nr_sect = 0;

	for (i = 0; i < ehdr.e_phnum; i++) {
		if (read(fd, &phdr, sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
			fprintf(stderr, "read %s failed: %s\n", file, strerror(errno));
			goto release_ret;
		}

		if (phdr.p_type == PT_LOAD || phdr.p_type == PT_DYNAMIC) {
			struct kcore_sect *sect = &acc->sects[acc->nr_sect++];
			sect->vaddr = phdr.p_vaddr;
			sect->vaddr_end = phdr.p_vaddr + phdr.p_memsz;
			sect->offset = phdr.p_offset;
		}
	}

	acc->fd = fd;
	return acc;

release_ret:
	kcore_access_destroy(acc);
close_ret:
	close(fd);
	return NULL;
}

int kcore_access_read(struct kcore_access *acc, unsigned long addr, void *buf, size_t sz)
{
	int i;

	for (i = 0; i < acc->nr_sect; ++i) {
		if (addr >= acc->sects[i].vaddr && addr < acc->sects[i].vaddr_end) {
			addr -= acc->sects[i].vaddr;
			addr += acc->sects[i].offset;
			break;
		}
	}
	
	if (i == acc->nr_sect)
		return -ENOENT;

	ssize_t n = pread(acc->fd, buf, sz, addr);
	if (n < 0)
		return -errno;

	return 0;
}