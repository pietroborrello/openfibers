#ifndef libfibers_h__
#define libfibers_h__

extern long libfibers_ioctl_fls_alloc(void);

extern long libfibers_ioctl_fls_get(long idx);

extern bool libfibers_ioctl_fls_free(long idx);

extern void libfibers_ioctl_fls_set(long idx, long value);

extern void libfibers_ioctl_ping(int fd);

extern void* libfibers_ioctl_create_fiber(void (*addr)(void *), void *args);

extern void* libfibers_ioctl_switch_to_fiber(void* fid);

extern void* libfibers_ioctl_convert_to_fiber(void);

#endif // libfibers_h__
