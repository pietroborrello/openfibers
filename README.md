# openfibers
Linux kernel module for User Level Threads (Fibers)

# Installation

## Module

```shell
$ make
$ sudo insmod ./openfibers.ko
```

## Shared Library
```shell
$ make
$ sudo make install
```

Then if you want to use is with Microsoft Fibers APIs, include in your code:
```c
extern long libfibers_ioctl_fls_alloc(void);
extern long libfibers_ioctl_fls_get(long idx);
extern bool libfibers_ioctl_fls_free(long idx);
extern void libfibers_ioctl_fls_set(long idx, long value);
extern void libfibers_ioctl_ping(int fd);
extern void *libfibers_ioctl_create_fiber(void (*addr)(void *), void *args);
extern void *libfibers_ioctl_switch_to_fiber(void *fid);
extern void *libfibers_ioctl_convert_to_fiber(void);

#define ConvertThreadToFiber() libfibers_ioctl_convert_to_fiber()
#define CreateFiber(dwStackSize, lpStartAddress, lpParameter) libfibers_ioctl_create_fiber(lpStartAddress, lpParameter)
#define SwitchToFiber(lpFiber) libfibers_ioctl_switch_to_fiber(lpFiber)
#define FlsAlloc(lpCallback) libfibers_ioctl_fls_alloc()
#define FlsFree(dwFlsIndex) libfibers_ioctl_fls_free(dwFlsIndex)
#define FlsGetValue(dwFlsIndex) libfibers_ioctl_fls_get(dwFlsIndex)
#define FlsSetValue(dwFlsIndex, lpFlsData) libfibers_ioctl_fls_set((dwFlsIndex), (long long)
```

And compile with `-lfibers`
