#ifndef __COV_KCORE_H__
#define __COV_KCORE_H__

struct kcore_access;

void kcore_access_destroy(struct kcore_access *acc);
struct kcore_access *kcore_access_create(const char *file);
int kcore_access_read(struct kcore_access *acc, unsigned long addr, void *buf, size_t sz);

#endif
