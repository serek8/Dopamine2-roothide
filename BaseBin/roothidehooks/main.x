#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#include "common.h"
#include <sys/sysctl.h>
#import <substrate.h>

#ifndef DEBUG
#define NSLog(args...)	
#endif

NSString* safe_getExecutablePath()
{
	char executablePathC[PATH_MAX];
	uint32_t executablePathCSize = sizeof(executablePathC);
	_NSGetExecutablePath(&executablePathC[0], &executablePathCSize);
	return [NSString stringWithUTF8String:executablePathC];
}

NSString* getProcessName()
{
	return safe_getExecutablePath().lastPathComponent;
}

int (*sysctlbyname_orig)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int sysctlbyname_hook(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	if (name && strstr(name, "developer")) {
		NSLog(@"sysctlbyname_hook=%{public}s", name);
	}
	return sysctlbyname_orig(name, oldp, oldlenp, newp, newlen);
}
// int __sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
void my_hook_sysctl_init(){
		void* __sysctlbyname_orig = NULL;
		MSHookFunction(&sysctlbyname, (void *) sysctlbyname_hook, (void **)&sysctlbyname_orig);
}

%ctor
{
	NSLog(@"roothidehooks coming... %@", safe_getExecutablePath());
	NSString *processName = getProcessName();
	/*if ([processName isEqualToString:@"installd"]) {
		extern void installdInit(void);
		installdInit();
	}
	else*/ if ([processName isEqualToString:@"cfprefsd"]) {
		extern void cfprefsdInit(void);
		cfprefsdInit();
	}
	else if ([processName isEqualToString:@"lsd"]) {
		extern void lsdInit(void);
		lsdInit();
	}
	else if ([processName isEqualToString:@"SpringBoard"]) {
		extern void sbInit(void);
		sbInit();
	}
}
