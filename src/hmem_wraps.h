#ifndef HMEMWRAPS_H
#define HMEMWRAPS_H

#define stat(__path,__buf) hstat(__path,__buf)
#define unlink(__path) hunlink(__path)
#define rename(__old,__new) hrename(__old,__new)
#define fopen(__filename,__mode) hfopen(__filename,__mode)
#define open(__path,__access, ...) hopen(__path,__access,##__VA_ARGS__)
#define write(__handle,__buffer,__len) hwrite(__handle,__buffer,__len)
#define read(__handle,__buffer,__len) hread(__handle,__buffer,__len)

int hstat(const char *path, struct stat *buf);
int hunlink(const char *path);
int hrename(const char *old, const char *new);
FILE *hfopen(const char *filename, const char *mode);
int hopen(const char *path, int access, ...);
int hread(int handle, void *buffer, unsigned len);
int hwrite(int handle, void *buffer, unsigned len);

#endif // HMEMWRAPS_H
