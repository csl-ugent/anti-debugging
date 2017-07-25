/* This research is supported by the European Union Seventh Framework Programme (FP7/2007-2013), project ASPIRE (Advanced  Software Protection: Integration, Research, and Exploitation), under grant agreement no. 609734; on-line at https://aspire-fp7.eu/. */

#ifndef __DEBUGGER_H__
#define __DEBUGGER_H__

/* C standard headers */
#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Linux headers */
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Architecture-specific headers */
#include <asm/ptrace.h>
#include <asm/unistd.h>

#define FL_S            0x1
#define FL_PREINDEX    0x2
#define FL_DIRUP    0x4
#define FL_WRITEBACK    0x8
#define FL_SPSR			0x10
#define FL_B FL_SPSR/* Cheat by using the FL_SPSR flag to store whether a we only load/store a byte */

/* Structs to be used in the code */
typedef struct t_sd_map_entry{
  uint32_t key;
  ptrdiff_t value;
} t_sd_map_entry;

/* This struct will contain a global state for every signal handled, and its contents will be
 * updated from the function wrapper code that will be inserted by Diablo.
 */
typedef struct t_sd_state{
  uintptr_t address;
  uintptr_t link;
  uintptr_t stack_pointer;
  struct pt_regs regs;
  pid_t process_pid;/* The actual PID of the process */
  pid_t recv_pid;/* The PID (actually TID) of the thread for whom waitpid returned */
} t_sd_state;

typedef void fun_moved_from_context();

/* The functions that will be used by Diablo */
#ifdef LINKIN_AFTER
void DIABLO_Debugger_Init();
#else
/* Make this function an initialization routine, executed as late as possible (because of the fork */
void DIABLO_Debugger_Init() __attribute__((constructor(65500)));
#endif

uintptr_t DIABLO_Debugger_Ldr(uintptr_t* base, uintptr_t offset, uint32_t flags);
void DIABLO_Debugger_Str(uintptr_t* base, uintptr_t offset, uintptr_t value, uint32_t flags);
void DIABLO_Debugger_Ldm(uintptr_t addr, void* regs, size_t nr_of_regs);
void DIABLO_Debugger_Stm(uintptr_t addr, void* regs, size_t nr_of_regs);

#endif
