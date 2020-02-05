/* This research is supported by the European Union Seventh Framework Programme (FP7/2007-2013), project ASPIRE (Advanced  Software Protection: Integration, Research, and Exploitation), under grant agreement no. 609734; on-line at https://aspire-fp7.eu/. */
/* AUTHORS:
 * Bert Abrath
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

/* The size of an address */
static size_t addr_size = sizeof(void*);

/* These variables will be filled in by Diablo */
t_sd_map_entry DIABLO_Debugger_addr_mapping[1] __attribute__((section (".data.addr_mapping"))) = {{ sizeof(DIABLO_Debugger_addr_mapping[0]), 0 }};
size_t DIABLO_Debugger_nr_of_entries = 42;
/* we will use a global variable to keep debugger state in handling signals. This works if we never handle multiple signals at once in the
 * debugger (through multithreading), as in that case we would need to use TLS.
 */
t_sd_state DIABLO_Debugger_global_state;

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

/* For writing /proc/PID/mem doesn't work on all kernels (not on Android 4.3 for example) so we use ptrace */
static void write_tracee_mem(void* buf, size_t size, uintptr_t addr)
{
  /* Write to the process word per word, except for non-word-aligned parts at the end */
  size_t bytes_read = 0;
  for (; bytes_read + addr_size <= size; addr += addr_size, bytes_read += addr_size)
  {
    uintptr_t value;
    memcpy(&value, buf + bytes_read, addr_size);
    ptrace(PTRACE_POKEDATA, debuggee_pid, (void*)addr, (void*)value);
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
    ptrace(PTRACE_POKEDATA, debuggee_pid, (void*)addr, (void*)value);
  }
}

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

  LOG("Initialize debugger. Number of entries: %zu\n", DIABLO_Debugger_nr_of_entries);
  LOG("Address of the mapping: %p\n", DIABLO_Debugger_addr_mapping);

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

static uintptr_t get_destination(uintptr_t id)
{
  /* Look up the the destination in the map */
  for(size_t iii = 0; iii < DIABLO_Debugger_nr_of_entries; iii++)
  {
    t_sd_map_entry loop = DIABLO_Debugger_addr_mapping[iii];

    if(loop.key == id)
    {
      LOG("Found value: %"PRIxPTR" and mapping sec: %p\n", loop.value, DIABLO_Debugger_addr_mapping);
      return loop.value + (uintptr_t)DIABLO_Debugger_addr_mapping;
    }
  }

  /* Haven't found a destination? That's bad! */
  LOG("Unknown address: application will be forced to shut down!\n");
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

static __attribute__((noreturn)) void handle_switch(pid_t debuggee_tid)
{
  struct pt_regs* regs = &DIABLO_Debugger_global_state.regs;/* Use regs variable as pointer to member to avoid more verbose code */

  /* Gather information from opposite process. In doing so, differentiate between handling switch as protected application, and as self-debugger */
  uintptr_t destination_address;
  uintptr_t link_address;
  if (selfdebugger_pid)
  {
    /* If we're the protected application, just steal the global state (including registers and addresses)
     * from the self-debugger.
     */
    read_tracee_mem(&DIABLO_Debugger_global_state, sizeof(DIABLO_Debugger_global_state), (uintptr_t)&DIABLO_Debugger_global_state);
    destination_address = DIABLO_Debugger_global_state.address;
    link_address = DIABLO_Debugger_global_state.link;

    /* Print out the information returned by the fragment we executed */
    LOG("ret addr: %"PRIxPTR"\n", destination_address);
    LOG("ret link: %"PRIxPTR"\n", link_address);
  }
  else
  {
    /* If we're the self-debugger, get the protected application's registers, and determine the address of the code
     * fragment that was requested.
     */
#ifndef ENABLE_LOGGING
    /* If we're not logging, get the registers now */
    ptrace(PTRACE_GETREGS, debuggee_tid, NULL, regs);
#endif

    /* Get the constant from the stack and adjust the stack pointer to 'pop' it */
    uintptr_t id = ptrace(PTRACE_PEEKTEXT, debuggee_tid, (void*)(regs->uregs[13]), NULL);
    regs->uregs[13] += addr_size;

    /* There's no link address, but fill in the address of the destination code fragment */
    destination_address = get_destination(id);
    link_address = 0;
  }

  /* Prepare the debuggee to be continued at the debug loop, then actually let it continue */
  struct pt_regs new_regs;
  ptrace(PTRACE_GETREGS, debuggee_tid, NULL, &new_regs);
  new_regs.uregs[15] = (uintptr_t)&return_to_debug_main;
  ptrace(PTRACE_SETREGS, debuggee_tid, NULL, &new_regs);
  ptrace(PTRACE_CONT, debuggee_tid, NULL, NULL);

  /* If a call occurred, update the link register */
  if (link_address)
    regs->uregs[14] = link_address;

  /* If we have a destination address, use it. Else just go to the next instruction */
  switch(destination_address)
  {
    case 0:
      regs->uregs[15] += addr_size;
      break;
    case 1:
      regs->uregs[15] = regs->uregs[14];
      break;
    default:
      regs->uregs[15] = destination_address;
  }

  /* Reset these fields, as they might get filled in by a code fragment */
  DIABLO_Debugger_global_state.link = 0;
  DIABLO_Debugger_global_state.address = 0;

  /* Do actual context switch */
  do_switch(&DIABLO_Debugger_global_state.regs);
}

static __attribute__((noreturn)) void debug_main()
{
  LOG("Debug loop entered\n");

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
    struct pt_regs* regs = &DIABLO_Debugger_global_state.regs;/* Use regs variable as pointer to member to avoid more verbose code */
    /* Get the registers. If logging is enabled, we do this now because so we can log them before potentially exiting */
    ret = ptrace(PTRACE_GETREGS, recv_tid, NULL, regs);
    if (ret == -1)
      LOG("PTRACE_GETREGS failed.\n");
    else
    {
      LOG("Register R0: %lx\n", regs->uregs[0]);
      LOG("Register R1: %lx\n", regs->uregs[1]);
      LOG("Register R2: %lx\n", regs->uregs[2]);
      LOG("Register R3: %lx\n", regs->uregs[3]);
      LOG("Register R4: %lx\n", regs->uregs[4]);
      LOG("Register R5: %lx\n", regs->uregs[5]);
      LOG("Register R6: %lx\n", regs->uregs[6]);
      LOG("Register R7: %lx\n", regs->uregs[7]);
      LOG("Register R8: %lx\n", regs->uregs[8]);
      LOG("Register R9: %lx\n", regs->uregs[9]);
      LOG("Register R10: %lx\n", regs->uregs[10]);
      LOG("Frame pointer: %lx\n", regs->uregs[11]);
      LOG("IP link: %lx\n", regs->uregs[12]);
      LOG("Stack pointer: %lx\n", regs->uregs[13]);
      LOG("Link register: %lx\n", regs->uregs[14]);
      LOG("From: %lx\n", regs->uregs[15]);
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
                /* If we're dealing with an exec we should simply detach from this PID and continue the debug loop */
                ptrace(PTRACE_DETACH, recv_tid, NULL, NULL);

                /* Remove the thread (this might close the debugger if there's no debuggees left) */
                removeThread(recv_tid);
                continue;
              case PTRACE_EVENT_CLONE:
              case PTRACE_EVENT_FORK:
              case PTRACE_EVENT_VFORK:
                {
                  /* If an event happened that resulted in new thread, we should trace it too */
                  pid_t new_pid;
                  ptrace(PTRACE_GETEVENTMSG, recv_tid, 0, &new_pid);
                  ptrace(PTRACE_CONT, new_pid, NULL, NULL);
                  addThread(new_pid);
                  break;
                }
              case PTRACE_EVENT_EXIT:
                ptrace(PTRACE_DETACH, recv_tid, NULL, NULL);
                continue;
              case PTRACE_EVENT_STOP:
                break;
              default:
                handle_switch(recv_tid);
            }

            signal = 0;/* Don't deliver this signal */
            break;
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

        /* Ignore all possible signals. Can't ever actually ignore SIGSTOP and SIGKILL, but can at least do the rest. Caution: Blocking
         * synchronously generated SIGBUS, SIGFPE, SIGILL, or SIGSEGV signals is undefined.
         */
        sigset_t ss;
        sigfillset(&ss);
        if (sigprocmask(SIG_BLOCK, &ss, NULL) == -1) {
          perror(0);
          exit(1);
        }

        /* Move process to a separate process group. This avoids signals sent from the terminal and
         * meant for the parent ending up at the child. A CTRL-Z on the commandline would stop our
         * child, which should actually be handling the SIGSTOP arriving for its tracee, instead of
         * stopping.
         */
        setpgid(0, 0);

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
