#include <libjailbreak/libjailbreak.h>
#include <mach-o/dyld.h>
#include <xpc/xpc.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sandbox.h>
#include <substrate.h>
#include <libjailbreak/log.h>
#include <libjailbreak/jbserver.h>

/*#undef JBLogDebug
void JBLogDebug(const char *format, ...)
{
	va_list va;
	va_start(va, format);

	FILE *launchdLog = fopen("/var/mobile/launchd-xpc.log", "a");
	vfprintf(launchdLog, format, va);
	fprintf(launchdLog, "\n");
	fclose(launchdLog);

	va_end(va);	
}*/

int xpc_receive_mach_msg(void *a1, void *a2, void *a3, void *a4, xpc_object_t *xOut);
int (*xpc_receive_mach_msg_orig)(void *a1, void *a2, void *a3, void *a4, xpc_object_t *xOut);
int xpc_receive_mach_msg_hook(void *a1, void *a2, void *a3, void *a4, xpc_object_t *xOut)
{
	JBLogDebug("xpc_receive_mach_msg_hook start");
	int r = xpc_receive_mach_msg_orig(a1, a2, a3, a4, xOut);
	JBLogDebug("xpc_receive_mach_msg_hook = %d", r);
	if (r == 0) {
		xpc_object_t xmsg = *xOut;
		char *description = xpc_copy_description(xmsg);
		JBLogDebug("xpc_receive_mach_msg_hook description = %s", description);
		if (xpc_dictionary_get_value(xmsg, "action")){
			JBLogDebug("xpc_receive_mach_msg_hook action");
		}
		int jb_ret = jbserver_received_xpc_message(&gGlobalServer, *xOut);
		JBLogDebug("jb_ret() = %d", jb_ret);
		if (jb_ret == 0) {
			// Returning non null here makes launchd disregard this message
			// For jailbreak messages we have the logic to handle them
			xpc_release(*xOut);
			return 22;
		}
	}
	return r;
}

void initXPCHooks(void)
{
	MSHookFunction(xpc_receive_mach_msg, (void *)xpc_receive_mach_msg_hook, (void **)&xpc_receive_mach_msg_orig);
}
