#ifndef _UAPI_FASTD_H
#define _UAPI_FASTD_H

enum {
	FASTD_SETFD_A_UNSPEC,
	FASTD_SETFD_A_FD,
	__FASTD_SETFD_A_LAST
};
#define FASTD_SETFD_A_MAX (__FASTD_SETFD_A_LAST - 1)

#endif /* _UAPI_FASTD_H */