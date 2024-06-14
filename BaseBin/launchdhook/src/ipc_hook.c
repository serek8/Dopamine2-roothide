#include <sandbox.h>
#include <substrate.h>
#include <libproc.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/log.h>
#include <libjailbreak/deny.h>

typedef struct{
    unsigned int val[8];
} my_audit_token_t;

int (*sandbox_check_by_audit_token_orig)(audit_token_t au, const char *operation, int sandbox_filter_type, ...);
int sandbox_check_by_audit_token_hook(audit_token_t au, const char *operation, int sandbox_filter_type, ...)
{
	va_list a;
	va_start(a, sandbox_filter_type);
	const char *name = va_arg(a, const char *);
	const void *arg2 = va_arg(a, void *);
	const void *arg3 = va_arg(a, void *);
	const void *arg4 = va_arg(a, void *);
	const void *arg5 = va_arg(a, void *);
	const void *arg6 = va_arg(a, void *);
	const void *arg7 = va_arg(a, void *);
	const void *arg8 = va_arg(a, void *);
	const void *arg9 = va_arg(a, void *);
	const void *arg10 = va_arg(a, void *);
	va_end(a);
	JBLogDebug("inside sandbox_check_by_audit_token_hook");
	if (name && operation) {
		JBLogDebug("inside if sandbox_check_by_audit_token_hook");
		JBLogDebug("operation = %s", operation);
		if (strcmp(operation, "mach-lookup") == 0) {
			JBLogDebug("name = %s", name);
			my_audit_token_t *mytoken = (uint8_t*)&au;
			for (int i = 0; i < 8; i++) {
				JBLogDebug("AuditToken[%d]: %02X", i, mytoken->val[i]);
			}
			JBLogDebug("AuditToken[PID]: %d", mytoken->val[5]);
			if (strncmp((char *)name, "cy:", 3) == 0 || strncmp((char *)name, "lh:", 3) == 0) {
								
				bool allow=true;
				char pathbuf[PATH_MAX]={0};
				pid_t pid = audit_token_to_pid(au);
				JBLogDebug("audit_token_to_pid = %d", pid);
				if(pid>0 && proc_pidpath(pid, pathbuf, sizeof(pathbuf))>0) {
					if(isBlacklisted(pathbuf)) {
						allow=false;
					} 
				}
				
				if(allow) {
					/* always allow */
					return 0;
				}
			}
		}
	}
	return sandbox_check_by_audit_token_orig(au, operation, sandbox_filter_type, name, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

void initIPCHooks(void)
{
	MSHookFunction(&sandbox_check_by_audit_token, (void *)sandbox_check_by_audit_token_hook, (void **)&sandbox_check_by_audit_token_orig);
}
