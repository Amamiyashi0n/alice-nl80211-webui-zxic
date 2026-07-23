#include <stddef.h>

#ifdef WPA_MINI_DYNAMIC
#include <ctype.h>

#define RTLD_LAZY 0x00001
#define RTLD_LOCAL 0

extern void *dlopen(const char *filename, int flags);
extern void *dlsym(void *handle, const char *symbol);

const __ctype_mask_t *__ctype_b;
const __ctype_touplow_t *__ctype_tolower;
const __ctype_touplow_t *__ctype_toupper;

void dynamic_runtime_init(void)
{
	void *libc;
	const __ctype_mask_t **ctype_b;
	const __ctype_touplow_t **ctype_tolower;
	const __ctype_touplow_t **ctype_toupper;

	libc = dlopen("libc.so.0", RTLD_LAZY | RTLD_LOCAL);
	if (!libc)
		return;

	ctype_b = (const __ctype_mask_t **)dlsym(libc, "__ctype_b");
	ctype_tolower = (const __ctype_touplow_t **)dlsym(libc,
		"__ctype_tolower");
	ctype_toupper = (const __ctype_touplow_t **)dlsym(libc,
		"__ctype_toupper");
	if (ctype_b)
		__ctype_b = *ctype_b;
	if (ctype_tolower)
		__ctype_tolower = *ctype_tolower;
	if (ctype_toupper)
		__ctype_toupper = *ctype_toupper;
}
#else
void dynamic_runtime_init(void)
{
}
#endif
