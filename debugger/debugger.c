/* This research is supported by the European Union Seventh Framework Programme (FP7/2007-2013), project ASPIRE (Advanced  Software Protection: Integration, Research, and Exploitation), under grant agreement no. 609734; on-line at https://aspire-fp7.eu/. */
/* AUTHORS:
 * Bert Abrath
 * Ilja Nevolin
 * Joris Wijnant
 */

#include "debugger.h"

/* We will use this signal to communicate with the mini-debugger */
#define SIGMINIDEBUGGER SIGUSR1

#ifdef ENABLE_LOGGING

#ifdef __ANDROID__
#include <android/log.h>
#define ANDROID_LOG(mesg, ...) __android_log_print(ANDROID_LOG_INFO, "MINIDEBUGGER", mesg, ##__VA_ARGS__)
#else
#define ANDROID_LOG(...)
#endif

#define LOG(mesg, ...) printf(mesg, ##__VA_ARGS__)
#else
#define LOG(...)
#define ANDROID_LOG(...)
#endif

/* Own version of tgkill */
#define my_tgkill(pid, tid, sig) syscall(__NR_tgkill, (pid), (tid), (sig))

/* Hack: this isn't present in the toolchain's ptrace.h unfortunately -_- */
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL (1 << 20)
#endif

/* Hack: this isn't present in the toolchain's prctl.h unfortunately -_- */
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

///////////////////////////////////////////////////////
//////////////////// OBFUSCATION //////////////////////
///////////////////////////////////////////////////////
static const bool IS_MUTILATED_ADDR_MAPPING = true;
static const unsigned int MUTILATION_MASK_ADR_MAP = 0xF0F0F0F0;

/* The size of an address */
static size_t addr_size = sizeof(void*);

/* These variables will be filled in by Diablo */
t_target_map_entry DIABLO_Debugger_target_map[1] __attribute__((section (".data.target_map"))) = {{ sizeof(DIABLO_Debugger_target_map[0]), 0 }};
size_t DIABLO_Debugger_nr_of_targets = 42;
/* we will use a global variable to keep debugger state in handling signals. This works if we never handle multiple signals at once in the
 * debugger (through multithreading), as in that case we would need to use TLS.
 */

static pid_t selfdebugger_pid;/* The PID of the self-debugger process */
static pid_t debuggee_pid;/* The PID of the debuggee process, i.e., the opposite process */
static char debug_stack[16384];
static ucontext_t debug_loop_context;

/* These static variables are used when reading memory from the debuggee */
static int mem_file;
static int mem_file_own;

/* For reading we can always use /proc/PID/mem */
static void read_tracee_mem(void* buf, size_t size, uintptr_t addr)
{
  lseek(mem_file, addr, SEEK_SET);
  if (read(mem_file, buf, size) == -1) {
    perror(0);
    exit(1);
  }
}

#define USE_MEM_FILE
#ifdef USE_MEM_FILE
static void write_tracee_mem(void* buf, size_t size, uintptr_t addr)
{
  lseek(mem_file, addr, SEEK_SET);
  if (write(mem_file, buf, size) == -1) {
    perror(0);
    exit(1);
  }
}
#else
/* For writing /proc/PID/mem doesn't work on all kernels (not on Android 4.3 for example) so we use ptrace */
static void write_tracee_mem(void* buf, size_t size, uintptr_t addr)
{
  /* Stop the debuggee, so we can use PTRACE requests to write to its address space */
  if (ptrace(PTRACE_INTERRUPT, debuggee_pid, 0, 0) == -1)
  {
    perror(0);
    exit(1);
  }
  waitpid(debuggee_pid, NULL, __WALL);

  /* Write to the process word per word, except for non-word-aligned parts at the end */
  size_t bytes_read = 0;
  for (; bytes_read + addr_size <= size; addr += addr_size, bytes_read += addr_size)
  {
    uintptr_t value;
    memcpy(&value, buf + bytes_read, addr_size);
    if (ptrace(PTRACE_POKEDATA, debuggee_pid, (void*)addr, (void*)value) == -1)
    {
      perror(0);
      exit(1);
    }
  }

  /* The remainder is unaligned to the word size. Unfortunately we can only write in words using the ptrace
   * API and would thus zero out (and thus overwrite) part of the word that should stay the same.
   */
  if (size - bytes_read)
  {
    /* We start by reading the entire word, which we will partially change */
    uintptr_t value;
    read_tracee_mem(&value, addr_size, addr);

    /* Change the requested part of the word */
    memcpy(&value, buf + bytes_read, size - bytes_read);

    /* Write the adapted word */
    if (ptrace(PTRACE_POKEDATA, debuggee_pid, (void*)addr, (void*)value) == -1)
    {
      perror(0);
      exit(1);
    }
  }

  /* Let the debuggee continue */
  if (ptrace(PTRACE_CONT, debuggee_pid, 0, 0) == -1)
  {
    perror(0);
    exit(1);
  }
}
#endif

/* Perform initialization for the debugger */
static bool init_debugger(pid_t target_pid)
{
  pid_t self_pid = getpid();
  debuggee_pid = target_pid;

#ifdef ENABLE_LOGGING
  /* Write stdout and stderr for the debugger to a file */
#ifdef __ANDROID__
#define LOG_PREFIX "/data/" /* We have to use an absolute path to a writable directory on Android */
#else
#define LOG_PREFIX
#endif

  char filename[260];/* Let's live dangerously */
  sprintf(filename, LOG_PREFIX "self_debugging_stdout.%d.%d", target_pid, self_pid);
  freopen(filename, "w", stdout);
  setlinebuf(stdout);

  sprintf(filename, LOG_PREFIX "self_debugging_stderr.%d.%d", target_pid, self_pid);
  freopen(filename, "w", stderr);
  setlinebuf(stderr);
#endif

  LOG("Initialize debugger. Number of entries: %zu\n", DIABLO_Debugger_nr_of_targets);
  LOG("Address of the mapping: %p\n", DIABLO_Debugger_target_map);

  /* Use the PID of the debuggee to open its mem_file */
  char str[80];
  sprintf(str, "/proc/%d/mem", target_pid);
  mem_file = open(str, O_RDWR);

  if(mem_file == -1)
  {
    LOG("Debuggee mem not found.");
    return false;
  }

  /* Now get our own PID and open our own mem_file */
  sprintf(str, "/proc/%d/mem", self_pid);
  mem_file_own = open(str, O_RDWR);

  if(mem_file_own == -1)
  {
    LOG("Own mem not found.");
    return false;
  }

  return true;
}

/* Perform finalization of debugger functionality */
static void fini_debugger()
{
  LOG("Finalizing debugger functionality.\n");

  /* Close the open file descriptors */
  close(mem_file);
  close(mem_file_own);

#ifdef ENABLE_LOGGING
  fclose(stdout);
  fclose(stderr);
#endif
}

/* Clean up and exit the debugger */
static __attribute__((noreturn)) void close_debugger()
{
  /* Clean up */
  fini_debugger();

  /* Exit this process */
  exit(0);
}

/* Some global information about the threads we are attached to. Keep an array of TID's we attached
 * to. We will use an arbitrary limit for the number of threads. */
#define MAX_NTHREADS 256
static pid_t tids[MAX_NTHREADS] = { 0 };
static size_t nr_of_threads = 0;/* Remember how many threads we are attached to, so we know when to shut down */

static size_t getThreadIndex(pid_t tid)
{
  for (size_t iii = 0; iii < nr_of_threads; iii++)
  {
    if (tids[iii] == tid)
      return iii;
  }

  /* If we didn't find it, return SIZE_MAX */
  return SIZE_MAX;
}

/* Returns true if we didn't have this thread already */
static bool addThread(pid_t tid)
{
  size_t index = getThreadIndex(tid);

  /* If the thread wasn't present, add it */
  if (index == SIZE_MAX)
  {
    tids[nr_of_threads] = tid;
    nr_of_threads++;
    return true;
  }
  else
    return false;
}

static void removeThread(pid_t tid)
{
  /* Get the index of the thread */
  size_t index = getThreadIndex(tid);
  if (index == SIZE_MAX)
  {
    LOG("Tried to remove thread with tid %d but we're not actually attached to it!", tid);
    return;
  }

  /* Update the datastructure */
  nr_of_threads--;
  if (nr_of_threads != index)
    tids[index] = tids[nr_of_threads];

  /* If we're not attachd to any threads anymore, close */
  if (nr_of_threads == 0)
   close_debugger();
}

/* Attach to all thread in the thread group (process) */
static void attachToThreadGroup(pid_t tgid)
{
  /* Get the task directory for this process */
  char dirname[100];
  sprintf(dirname, "/proc/%d/task", tgid);
  DIR* proc_dir = opendir(dirname);

  if (!proc_dir)
  {
    ANDROID_LOG("Didn't manage to open the task directory for PID %d.", tgid);
    exit(-2);
  }

  /* Keep looping over the directory and attempting to attach to threads. If we attached to
   * a new thread, loop again.
   */
  bool attached;
  do
  {
    /* Iterate over the files. There is an entry for every thread in the group, its name being the tid */
    attached = false;
    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != NULL)
    {
      if(entry->d_name[0] == '.')
        continue;

      pid_t tid = atoi(entry->d_name);

      /* If we already had this thread, just continue and don't attach */
      if (getThreadIndex(tid) != SIZE_MAX)
        continue;

      /* Start tracing the thread. If we're not allowed to ptrace, simply exit. */
      if (ptrace(PTRACE_SEIZE, tid, NULL, (void*) (PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL)))
      {
        /* We just read the thread's TID from /proc. If it does not exist anymore, it just died and we'll ignore it. */
        if (errno == ESRCH)
          continue;
        /* We might not have the permissions to attach at all */
        else if (errno == EPERM)
          ANDROID_LOG("Not allowed to ptrace! PID: %d. TID: %d.", tgid, tid);
        /* Unknown other error */
        else
          ANDROID_LOG("PTRACE_SEIZE not working! PID: %d. TID: %d.", tgid, tid);

        exit(-3);
      }

      /* Add this thread to the datastructure. */
      addThread(tid);
      attached = true;

      ANDROID_LOG("Attached to PID: %d. TID: %d.", tgid, tid);
    }

    /* Go back to the beginning of the directory */
    rewinddir(proc_dir);
  } while(attached);

  /* Close the directory */
  closedir(proc_dir);
}

/* Takes as argument the pid of the thread for whom we received the signal. We shouldn't stop this thread as
 * it is already stopped, and detach from this thread as last.
 */
static void detachFromThreadGroup(pid_t current)
{
  /* Stop all the threads we are attached to */
  for (size_t iii = 0; iii < nr_of_threads; iii++)
  {
    if (tids[iii] == current)
      continue;/* Already stopped */

    /* Send a signal to stop the thread and catch it, leave the thread in stopped state before we detach it */
    LOG("Stopping PID %d, TID %d.\n", debuggee_pid, tids[iii]);
    my_tgkill(debuggee_pid, tids[iii], SIGSTOP);
    waitpid(tids[iii], NULL, __WALL);
  }

  /* Clear all signals still pending. One of them might stop the process after we detached.. */
  pid_t recv;
  int status;
  while (recv = waitpid(-1, &status, WNOHANG | __WALL), recv != 0)
  {
    /* If we see a SIGSTOP signal from an unknown PID it must be new thread, detach from it */
    if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP) && (getThreadIndex(recv) == SIZE_MAX))
    {
      /* Detach from the thread and send two extra SIGCONT's just for good measure */
      ptrace(PTRACE_DETACH, recv, NULL, NULL);
      my_tgkill(debuggee_pid, recv, SIGCONT);
      my_tgkill(debuggee_pid, recv, SIGCONT);

      LOG("During detach received signal from new thread %d. We detached from it.\n", recv);
      continue;
    }
    LOG("During detach, handled unknown signal. This is not good.\n");
  }

  /* Start detaching */
  for (size_t iii = 0; iii < nr_of_threads; iii++)
  {
    if (tids[iii] == current)
      continue;

    LOG("Detaching from %d.\n", tids[iii]);
    ptrace(PTRACE_DETACH, tids[iii], NULL, NULL);

  }

  /* The last thread we detach from is the one that is stuck in the finalization routine */
  LOG("Detaching from %d.\n", current);
  ptrace(PTRACE_DETACH, current, NULL, NULL);
}

static __attribute__((noreturn)) void return_to_debug_main()
{
  setcontext(&debug_loop_context);

  /* Should never get here, unless setcontext failed */
  LOG("The function setcontext failed!\n");
  close_debugger();
}

static uintptr_t decode_address_unobfuscated(struct pt_regs* regs)
{
  /* Get the constant from the stack and adjust the stack pointer to 'pop' it */
  uintptr_t id;
  read_tracee_mem(&id, addr_size, regs->uregs[13]);
  regs->uregs[13] += addr_size;

  /* Look up the the destination in the map */
  for(size_t iii = 0; iii < DIABLO_Debugger_nr_of_targets; iii++)
  {
    t_target_map_entry loop = DIABLO_Debugger_target_map[iii];

    if(loop.key == id)
    {
      LOG("Found value: %"PRIxPTR" for id: %"PRIxPTR"\n", loop.value, id);
      if (IS_MUTILATED_ADDR_MAPPING) {
        uintptr_t ret = (loop.value ^ (uintptr_t)DIABLO_Debugger_target_map);
        ret ^= MUTILATION_MASK_ADR_MAP;
        return ret;
      }
      else
        return loop.value + (uintptr_t)DIABLO_Debugger_target_map;
    }
  }

  return 0;
}

static bool verify_target_destination(uintptr_t dest)
{
  /* Not an actual destination, but a fake destination signaling a return */
  if (dest == (uintptr_t)DIABLO_Debugger_target_map)
    return true;

  /* If 'dest' is a valid address, we should be able to find the corresponding entry in the map */
  for(size_t iii = 0; iii < DIABLO_Debugger_nr_of_targets; iii++)
  {
    t_target_map_entry loop = DIABLO_Debugger_target_map[iii];

    /* Decode the (possibly mutilated) address value for this entry */
    uintptr_t val;
    if (IS_MUTILATED_ADDR_MAPPING) {
      val = (loop.value ^ (uintptr_t)DIABLO_Debugger_target_map);
      val ^= MUTILATION_MASK_ADR_MAP;
    }
    else
      val = loop.value + (uintptr_t)DIABLO_Debugger_target_map;

    /* Check whether we have a match */
    if (val == dest)
      return true;
  }

  /* No specific fragment requested, probably accidental signal */
  return false;
}

static uintptr_t decode_address_fpe(struct pt_regs* regs)
{
  /*
    This code is very sensitive to your ARM version.
    It uses bit wise operations to extract information from 32bit values.
    This is very relative to how your ARM machine instructions are encoded.
    Please adjust this code if it's unaligned with your situation.
  */

  //lets extract hex instruction pointed to by PC
  uintptr_t pc = regs->uregs[15];  //from the address where SIGSEGV occured
  uintptr_t pcins;
  read_tracee_mem(&pcins, addr_size, pc);

  // find register which is the numerator : bits 16, 17, 18 & 19.
  unsigned int regN = (pcins & 0x000F0000) >> 16;

  //we have to find *to*, the destination address which is encoded into the ill_addr.
  uintptr_t ill_addr_encoded = regs->uregs[regN];

  return ill_addr_encoded ^ 0xffffffff ^ pc;
}

static uintptr_t decode_address_segv_RW(struct pt_regs* regs, uintptr_t fault_address)
{
  /*
    This code is very sensitive to your ARM version.
    It uses bit wise operations to extract information from 32bit values.
    This is very relative to how your ARM machine instructions are encoded.
    Please adjust this code if it's unaligned with your situation.
  */

  //update: we no longer have to push the register which contains ill_addr, we can extract it from hex value of PC pointer.
  //regs->uregs[13] += addr_size; //pop from stack

  //lets extract hex instruction pointed to by PC
  uintptr_t pc = regs->uregs[15];  //from the address where SIGSEGV occured
  uintptr_t pcins;
  read_tracee_mem(&pcins, addr_size, pc);

  int immed = 255;
  unsigned int opcode = (pcins & 0xFFF00000) >> 20;
  unsigned int MASK = 0xffffffff;
  switch (opcode) {

    case 0xE58: // STR
    case 0xE59: // LDR
    case 0xE5A: // STR + writeback pre-index
    case 0xE5B: // LDR + writeback pre-index
    case 0xE48: // STR + writeback post-index
    case 0xE49: // LDR + writeback post-index

    case 0xE5C: // STRB
    case 0xE5D: // LDRB
    case 0xE5E: // STRB + writeback pre-index
    case 0xE5F: // LDRB + writeback pre-index
    case 0xE4C: // STRB + writeback post-index
    case 0xE4D: // LDRB + writeback post-index
      immed = (pcins & 0x00000FFF);
      break;

    case 0xE50: // STR (negative immediate)
    case 0xE51: // LDR (negative immediate)
    case 0xE52: // STR (negative immediate) + writeback pre-index
    case 0xE53: // LDR (negative immediate) + writeback pre-index
    case 0xE40: // STR (negative immediate) + writeback post-index
    case 0xE41: // LDR (negative immediate) + writeback post-index

    case 0xE54: // STRB (negative immediate)
    case 0xE55: // LDRB (negative immediate)
    case 0xE56: // STRB (negative immediate) + writeback pre-index
    case 0xE57: // LDRB (negative immediate) + writeback pre-index
    case 0xE44: // STRB (negative immediate) + writeback post-index
    case 0xE45: // LDRB (negative immediate) + writeback post-index
      immed = -(pcins & 0x00000FFF);
      break;

    case 0xE1C: // STRH
    case 0xE1D: // LDRH & LDRSH & LDRSB
    case 0xE1E: // STRH + writeback pre-index
    case 0xE1F: // LDRH & LDRSH & LDRSB + writeback pre-index
    case 0xE0C: // STRH + writeback post-index
    case 0xE0D: // LDRH & LDRSH & LDRSB + writeback post-index
      immed = (pcins & 0x0000000F) | ((pcins & 0x00000F00)>>4);
      break;

    case 0xE14: // STRH (negative immediate)
    case 0xE15: // LDRH & LDRSH & LDRSB (negative immediate)
    case 0xE16: // STRH (negative immediate) + writeback pre-index
    case 0xE17: // LDRH & LDRSH & LDRSB (negative immediate) + writeback pre-index
    case 0xE04: // STRH (negative immediate) + writeback pre-index
    case 0xE05: // LDRH & LDRSH & LDRSB (negative immediate) + writeback pre-index
      immed =- ((pcins & 0x0000000F) | ((pcins & 0x00000F00)>>4));
      break;

    case 0xE88: // STM
    case 0xE89: // LDM
      immed = 0;
      break;

    default:
      LOG("WHOOPS err #469 -- opcode %02X not implemented\n", opcode);
      return 0;
  }

  return ((fault_address+immed) ^ pc ^ MASK) ; //we have to find *to*, the destination address which is encoded into the ill_addr.
}

static uintptr_t decode_address_segv_X(struct pt_regs* regs, uintptr_t fault_address)
{
  uint32_t MASK = 0xC0000000;
  /*  we use 0xC0000000 instead of 0xFFFFFFFF
      simply because eg: 0xFFFFFFFF - 0x800C = 0xFFFF7FF3
      when the branch happens, the kernel/CPU will correct it
      and the PC register is changed to 0xFFFF7FF2 (using a heuristic for alignment)
      but if we add to 0xC0000000 we don't have this problem.
      */

  // pop LR from stack:
  uintptr_t LRreg;
  read_tracee_mem(&LRreg, addr_size, regs->uregs[13]);
  regs->uregs[13] += addr_size; //fix stack pointer
  regs->uregs[14] = LRreg; //backup the LR register

  return ((fault_address) ^ MASK) ; //we have to find *to*, the destination address which is encoded into the ill_addr.
}

static uintptr_t get_destination(pid_t debuggee_tid, unsigned int signal, struct pt_regs* regs,  bool is_selfdebugger)
{
  switch (signal)
  {
    case SIGTRAP:
      return decode_address_unobfuscated(regs);
    case SIGFPE:
        return decode_address_fpe(regs);
    case SIGBUS:
    case SIGILL:
    case SIGSEGV:
      {
        /* Gather more information on the signal */
        siginfo_t siginfo;
        ptrace(PTRACE_GETSIGINFO, debuggee_tid, NULL, &siginfo);
        uintptr_t fault_address = (uintptr_t)siginfo.si_addr;
        uintptr_t pc = regs->uregs[15];
        LOG("fault address: %"PRIxPTR"\n", fault_address);
        LOG("PC: %"PRIxPTR"\n", pc);

        /* If the PC **is** the fault address, we lack execute permissions. Else, we lack
         * read or write permissions.
         */
        if (fault_address == pc)
          return decode_address_segv_X(regs, fault_address);
        else
          return decode_address_segv_RW(regs, fault_address);
      }
  }

  LOG("Unspecified obfuscation method: application will be forced to shut down!\n");
  close_debugger();
}

/* Do the switch to the new context, by switching to these registers */
static __attribute__((noreturn, naked)) void do_switch(struct pt_regs* regs)
{
  __asm volatile (
      "MOV SP, %[input_regs]\n\t" /* First move the registers to SP, as we get a Diablo FATAL when doing the LDM from R0 */
      "LDM SP, {R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, FP, IP, SP, LR, PC}\n\t"
      : /* No output operands */
      : [input_regs] "r" (regs)
      );
}

/* This function only returns if the signal turns out not to have been protection-related */
static void handle_switch(pid_t debuggee_tid, unsigned int signal, sigset_t old_ss)
{
  /* Get the actual current registers of the debuggee */
  struct pt_regs regs;
  ptrace(PTRACE_GETREGS, debuggee_tid, NULL, &regs);

  /* Determine the destination address */
  bool is_selfdebugger = !selfdebugger_pid;
  uintptr_t destination_address = get_destination(debuggee_tid, signal, &regs, is_selfdebugger);

  /* Verify whether this is a valid target. If not, we return so that the signal can be passed on to the debuggee */
  if (!verify_target_destination(destination_address))
  {
    LOG("Target validation failed! Assuming this is an genuine signal...\n");
    return;
  }

  /* THIS IS THE POINT OF NO RETURN... */

  /* Prepare the debuggee to be continued at the debug loop, then actually let it continue */
  regs.uregs[15] = (uintptr_t)&return_to_debug_main;
  ptrace(PTRACE_SETREGS, debuggee_tid, NULL, &regs);
  ptrace(PTRACE_CONT, debuggee_tid, NULL, NULL);

  /* If the destination address is that of the mapping, it's a return */
  if (destination_address == (uintptr_t)DIABLO_Debugger_target_map)
  {
      LOG("Returning!!\n");
      destination_address = 1;
  }

  /* If we have a destination address, use it. Else just go to the next instruction */
  switch(destination_address)
  {
    case 0:
      regs.uregs[15] += addr_size;
      break;
    case 1:
      regs.uregs[15] = regs.uregs[14];
      break;
    default:
      regs.uregs[15] = destination_address;
  }

  /* TODO: In principle, we need to synchronize here, make sure the debuggee is running already before we continue */
  /* Restore previous signal blocking mask */
  if (sigprocmask(SIG_SETMASK, &old_ss, NULL) == -1) {
    perror(0);
    exit(1);
  }

  /* Do actual context switch */
  LOG("Going to switch to: %lx\n", regs.uregs[15]);
  do_switch(&regs);
}

static __attribute__((noreturn)) void debug_main()
{
  LOG("Debug loop entered\n");

  /* Ignore all possible signals. Can't ever actually ignore SIGSTOP and SIGKILL, but can at least do the rest. Caution: Blocking
   * synchronously generated SIGBUS, SIGFPE, SIGILL, or SIGSEGV signals is undefined. Get the old set of ignored signals,
   * so we can restore it on the switch back.
   */
  sigset_t ss, old_ss;
  sigfillset(&ss);
  if (sigprocmask(SIG_BLOCK, &ss, &old_ss) == -1) {
    perror(0);
    exit(1);
  }

  /* Infinite loop, handling signals until the debuggee exits */
  while(true)
  {
    int status, ret;

    /* Wait for a signal from the debuggee. This is either the self-debugger, in which case we explicitly use its PID, or any of the
     * application's threads, in which case we wait for all PIDs (-1). Not sure if the __WALL is required though.
     */
    pid_t recv_tid = waitpid(selfdebugger_pid ? selfdebugger_pid : -1, &status, __WALL);

    /* If waitpid does not succeed, the process is already dead */
    if (recv_tid == -1)
    {
      LOG("The debuggee has terminated (waitpid returns -1)\n");
      close_debugger();
    }

    LOG("Debugger entered for PID: %d\n", recv_tid);

#ifdef ENABLE_LOGGING
    struct pt_regs regs;/* Use regs variable as pointer to member to avoid more verbose code */
    /* Get the registers. If logging is enabled, we do this now because so we can log them before potentially exiting */
    ret = ptrace(PTRACE_GETREGS, recv_tid, NULL, &regs);
    if (ret == -1)
      LOG("PTRACE_GETREGS failed.\n");
    else
    {
      LOG("Register R0: %lx\n", regs.uregs[0]);
      LOG("Register R1: %lx\n", regs.uregs[1]);
      LOG("Register R2: %lx\n", regs.uregs[2]);
      LOG("Register R3: %lx\n", regs.uregs[3]);
      LOG("Register R4: %lx\n", regs.uregs[4]);
      LOG("Register R5: %lx\n", regs.uregs[5]);
      LOG("Register R6: %lx\n", regs.uregs[6]);
      LOG("Register R7: %lx\n", regs.uregs[7]);
      LOG("Register R8: %lx\n", regs.uregs[8]);
      LOG("Register R9: %lx\n", regs.uregs[9]);
      LOG("Register R10: %lx\n", regs.uregs[10]);
      LOG("Frame pointer: %lx\n", regs.uregs[11]);
      LOG("IP link: %lx\n", regs.uregs[12]);
      LOG("Stack pointer: %lx\n", regs.uregs[13]);
      LOG("Link register: %lx\n", regs.uregs[14]);
      LOG("From: %lx\n", regs.uregs[15]);
    }
#endif

    /* Look at the status information to decide what to do */
    if (WIFEXITED(status))
    {
      LOG("Debuggee has terminated normally with exit status %d.\n", WEXITSTATUS(status));

      /* Remove the thread (this might close the debugger if there's no debuggees left) */
      removeThread(recv_tid);
      continue;
    }
    else if (WIFSIGNALED(status))
    {
      LOG("Debuggee has been terminated by a signal with number %d.\n", WTERMSIG(status));

      /* Remove the thread (this might close the debugger if there's no debuggees left) */
      removeThread(recv_tid);
      continue;
    }
    else if (WIFSTOPPED(status))
    {
      unsigned int signal = WSTOPSIG(status);
      const unsigned int event = (unsigned int) status >> 16;
      LOG("Debuggee has been stopped by a signal with number %d and event number %u.\n", signal, event);
      switch (event)
      {
        case PTRACE_EVENT_CLONE:
          LOG("CLONE EVENT.\n");
          break;
        case PTRACE_EVENT_EXEC:
          LOG("EXEC EVENT.\n");
          break;
        case PTRACE_EVENT_EXIT:
          LOG("EXIT EVENT.\n");
          break;
        case PTRACE_EVENT_FORK:
          LOG("FORK EVENT.\n");
          break;
        case PTRACE_EVENT_STOP:
          LOG("STOP EVENT.\n");
          break;
        case PTRACE_EVENT_VFORK:
          LOG("VFORK EVENT.\n");
          break;
      }

      switch (signal)
      {
        /* If we receive this signal, the program has exited or the shared object has been unloaded */
        case SIGMINIDEBUGGER:
          {
            LOG("Debuggee signals to shut down.\n");

            /* Detach from the thread group */
            detachFromThreadGroup(recv_tid);

            /* Close the debugger */
            close_debugger();

            /* Let the debuggee continue its shutting down, but don't deliver signal */
            signal = 0;
            break;
          }

        /* If the signal is a stopping signal, it might actually be a group-stop */
        case SIGSTOP:
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
          {
            if (event == PTRACE_EVENT_STOP)
            {
              LOG("Group-stop.\n");

              ptrace(PTRACE_LISTEN, recv_tid, NULL, NULL);
              continue;
            }
            break;
          }

        /* If the signal is SIGTRAP, an event might have happened */
        case SIGTRAP:
          {
            switch (event)
            {
              case PTRACE_EVENT_EXEC:
                {
                  /* If we're dealing with an exec we should simply detach from this PID and continue the debug loop */
                  ptrace(PTRACE_DETACH, recv_tid, NULL, NULL);

                  /* Remove the thread (this might close the debugger if there's no debuggees left) */
                  removeThread(recv_tid);
                  continue;
                }
              case PTRACE_EVENT_CLONE:
              case PTRACE_EVENT_FORK:
              case PTRACE_EVENT_VFORK:
                {
                  /* If an event happened that resulted in new thread, we should trace it too */
                  pid_t new_pid;
                  ptrace(PTRACE_GETEVENTMSG, recv_tid, 0, &new_pid);
                  ptrace(PTRACE_CONT, new_pid, NULL, NULL);
                  addThread(new_pid);
                  signal = 0;/* Don't deliver this signal */
                  break;
                }
              case PTRACE_EVENT_EXIT:
                {
                  ptrace(PTRACE_DETACH, recv_tid, NULL, NULL);
                  continue;
                }
              case PTRACE_EVENT_STOP:
                {
                  signal = 0;/* Don't deliver this signal */
                  break;
                }
              default:
                handle_switch(recv_tid, signal, old_ss);
            }

            break;
          }

        /* Obfuscated signaling */
        case SIGBUS:
        case SIGFPE: //arithmetic exception: such as divide by zero ; should be SIGFPE (8)
        case SIGILL:
        case SIGSEGV:
          {
            handle_switch(recv_tid, signal, old_ss);
          }
      }

      /* Continue the debuggee and - possibly - deliver signal */
      ptrace(PTRACE_CONT, recv_tid, NULL, (void*) signal);
      continue;
    }
#ifndef __ANDROID__ /* Apparently Android does not support this */
    else if (WIFCONTINUED(status))
    {
      LOG("Debuggee has been continued by SIGCONT.\n");
      continue;
    }
#endif
    else
    {
      LOG("Didn't manage to decipher the status. That's probably not good.");
      continue;
    }
  }
}

/* The finalization routine. Its invocation means the program is ending or the library is being unloaded. */
static void fini_routine()
{
  ptrace(PTRACE_DETACH, selfdebugger_pid, NULL, NULL);
  ANDROID_LOG("Finalization routine. Signaling the mini-debugger to shut down.");

  /* Cleaning up debugger functionality */
  fini_debugger();

  /* Let the mini-debugger know it is to stop */
  raise(SIGMINIDEBUGGER);
}

static void passthrough_signal_handler(int signal)
{
  LOG("SIGNAL HANDLER: Passing through signal %d.\n", signal);

  /* Inject signal. Can't use PTRACE_CONT for this, its result is not guaranteed */
  if (kill(debuggee_pid, signal) == -1)
  {
    perror(0);
    exit(1);
  }
}

/* The inialization routine that will fork the process. The child becomes the debugger and debugs the parent */
void DIABLO_Debugger_Init()
{
  volatile unsigned long can_run = 0;

  /* Allow everyone to ptrace. After the fork we'll change it to the specific PID of the child. This could be improved
   * by using some active looping in the child's attaching logic, perhaps? */
  prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);

  /* Get the parent PID before forking */
  pid_t parent_pid = getpid();
  pid_t child_pid = fork();

  /* Set up SIGCHLD ignoring. This means some SIGCHLDs won't even be sent (and presented to the tracer through ptrace-stop) anymore. */
  // TODO: make this temporary for protected application?
  struct sigaction sa;
  sa.sa_handler = SIG_IGN; //handle signal by ignoring
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(SIGCHLD, &sa, 0) == -1) {
    perror(0);
    exit(1);
  }

  switch(child_pid)
  {
    case -1:/*error*/
      {
        perror("fork()");
        ANDROID_LOG("Failed to fork! PID: %d.", parent_pid);
        exit(-1);
      }
    case 0:/*child process*/
      {
        /* Only allow parent to ptrace */
        prctl(PR_SET_PTRACER, parent_pid);

        /* Move process to a separate process group. This avoids signals sent from the terminal and
         * meant for the parent ending up at the child. A CTRL-Z on the commandline would stop our
         * child, which should actually be handling the SIGSTOP arriving for its tracee, instead of
         * stopping.
         */
        setpgid(0, 0);

        /* Install signal handler for SIGTERM. If the self-debugger receives a SIGTERM, we actually
         * want the protected applicaton to get it, and perform a graceful shutdown.
         */
        struct sigaction sb;
        sb.sa_handler = passthrough_signal_handler;
        sigemptyset(&sb.sa_mask);
        sb.sa_flags = 0;
        if (sigaction(SIGTERM, &sb, 0) == -1) {
          perror(0);
          exit(1);
        }

        /* Attach to all thread in the thread group (process) */
        ANDROID_LOG("Mini-debugger has been forked and will start attaching!");
        attachToThreadGroup(parent_pid);

        /* Initialize the debugger and start the debugging loop */
        if (init_debugger(parent_pid))
        {
          /* Stop the parent */
          ptrace(PTRACE_INTERRUPT, parent_pid, 0, 0);
          waitpid(parent_pid, NULL, __WALL);

          /* Allow the parent to continue */
          ptrace(PTRACE_POKEDATA, parent_pid, (void*)&can_run, (void*)1);
          ptrace(PTRACE_CONT, parent_pid, 0, 0);

          /* Right before we go into the debug loop, set the context to return to */
          ANDROID_LOG("Start main loop");
          getcontext(&debug_loop_context);
          debug_main();
        }

        close_debugger();
      }
  }

  /* Only allow child to ptrace */
  prctl(PR_SET_PTRACER, child_pid);

  /* Install the finalization routine to executed when the parent exits */
  atexit(fini_routine);

  /* In the parent, we'll spin on this variable until the child signals we can continue */
  while (!can_run);

  /* Have the parent attach to the self-debugger */
  selfdebugger_pid = child_pid;
  ptrace(PTRACE_SEIZE, selfdebugger_pid, NULL, (void*)  PTRACE_O_EXITKILL);
  init_debugger(selfdebugger_pid);

  /* Create the context for the debug loop */
  getcontext(&debug_loop_context);
  debug_loop_context.uc_stack.ss_sp = debug_stack;
  debug_loop_context.uc_stack.ss_size = sizeof(debug_stack);
  debug_loop_context.uc_link = NULL;
  makecontext(&debug_loop_context, &debug_main, 0);
}

uintptr_t DIABLO_Debugger_Ldr(uintptr_t* base, uintptr_t offset, uint32_t flags)
{
  uintptr_t addr = *base + ((flags & FL_DIRUP) ? offset : -offset);
  uintptr_t dest = (flags & FL_PREINDEX) ? addr : *base;
  LOG("Base: %p, Offset: %x, flags: %u.\n", base, offset, flags);
  LOG("Going to load something from %x.\n", dest);

  uintptr_t value = 0;
  read_tracee_mem(&value, (flags & FL_B) ? 1 : addr_size, dest);

  if ((flags & FL_WRITEBACK))
    *base = addr;

  LOG("Loaded value %x.\n", value);
  return value;
}

void DIABLO_Debugger_Str(uintptr_t* base, uintptr_t offset, uintptr_t value, uint32_t flags)
{
  uintptr_t addr = *base + ((flags & FL_DIRUP) ? offset : -offset);
  uintptr_t dest = (flags & FL_PREINDEX) ? addr : *base;
  LOG("Base: %p, Offset: %x, flags: %u.\n", base, offset, flags);
  LOG("Going to store %x to %x.\n", value, dest);

  write_tracee_mem(&value, (flags & FL_B) ? 1 : addr_size, dest);

  if(flags & FL_WRITEBACK)
    *base = addr;

  LOG("Store successful.\n");
}

void DIABLO_Debugger_Ldm(uintptr_t addr, void* regs, size_t nr_of_regs)
{
  read_tracee_mem(regs, addr_size * nr_of_regs, addr);
}

void DIABLO_Debugger_Stm(uintptr_t addr, void* regs, size_t nr_of_regs)
{
  write_tracee_mem(regs, addr_size * nr_of_regs, addr);
}
