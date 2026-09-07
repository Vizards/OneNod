//go:build darwin

package beholdercontext

/*
#cgo LDFLAGS: -lproc
#define __APPLE_API_UNSTABLE 1
#include <libproc.h>
#include <string.h>
#include <sys/proc_info.h>

static int beholder_hook_process_snapshot(pid_t pid, struct proc_bsdinfo *snapshot) {
    memset(snapshot, 0, sizeof(*snapshot));
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, snapshot, sizeof(*snapshot));
    if (size != (int)sizeof(*snapshot) || snapshot->pbi_pid != (uint32_t)pid) return -1;
    return 0;
}

static int beholder_hook_process_path(pid_t pid, char *output, size_t output_size) {
    if (output_size == 0) return -1;
    memset(output, 0, output_size);
    return proc_pidpath(pid, output, (uint32_t)output_size) > 0 ? 0 : -1;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

func inspectHookProcess(pid int) (hookProcessIdentity, error) {
	var snapshot C.struct_proc_bsdinfo
	if C.beholder_hook_process_snapshot(C.pid_t(pid), &snapshot) != 0 {
		return hookProcessIdentity{}, errors.New("process snapshot unavailable")
	}
	pathBuffer := make([]byte, 4096)
	path := ""
	if C.beholder_hook_process_path(
		C.pid_t(pid), (*C.char)(unsafe.Pointer(&pathBuffer[0])), C.size_t(len(pathBuffer)),
	) == 0 {
		path = C.GoString((*C.char)(unsafe.Pointer(&pathBuffer[0])))
	}
	return hookProcessIdentity{
		PID:               int(snapshot.pbi_pid),
		ParentPID:         int(snapshot.pbi_ppid),
		StartSeconds:      uint64(snapshot.pbi_start_tvsec),
		StartMicroseconds: uint64(snapshot.pbi_start_tvusec),
		UID:               uint32(snapshot.pbi_uid),
		RealUID:           uint32(snapshot.pbi_ruid),
		Path:              path,
	}, nil
}
