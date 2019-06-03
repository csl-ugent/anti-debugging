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

/* The size of an address */
static size_t addr_size = sizeof(void*);

/* These variables will be filled in by Diablo */
t_sd_map_entry DIABLO_Debugger_addr_mapping[1] __attribute__((section (".data.addr_mapping"))) = {{ sizeof(DIABLO_Debugger_addr_mapping[0]), 0 }};
size_t DIABLO_Debugger_nr_of_entries = 42;
/* we will use a global variable to keep debugger state in handling signals. This works if we never handle multiple signals at once in the
 * debugger (through multithreading), as in that case we would need to use TLS.
 */
t_sd_state DIABLO_Debugger_global_state;

static pid_t debugger_pid;

/* These static variables are used when reading memory from the debuggee */
static uintptr_t sp_debuggee;
static uintptr_t sp_debugger;
static ptrdiff_t sp_offset;
static int mem_file;
static int mem_file_own;

/* Perform initialization for the debugger */
static bool init_debugger(pid_t target_pid)
{
  pid_t self_pid = getpid();
  DIABLO_Debugger_global_state.process_pid = target_pid;

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

  /* Map memory that will serve as a stack when executing application code */
  sp_debugger = (uintptr_t) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  LOG("Debugger stack pointer: %"PRIxPTR"\n", sp_debugger);

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

/* Clean up and exit the debugger */
static void close_debugger()
{
  LOG("Closing debugger.\n");

  /* Close the open file descriptors */
  close(mem_file);
  close(mem_file_own);

#ifdef ENABLE_LOGGING
  fclose(stdout);
  fclose(stderr);
#endif

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

/* TODO: This entire function should be cleaner */
static void set_stack_pointer(uintptr_t pointer)
{
  sp_debuggee = pointer - (pointer & 0xfff);

  sp_offset = sp_debugger - sp_debuggee;

  LOG("Debuggee stack pointer: %"PRIxPTR"\nOffset: %tx\n", sp_debuggee, sp_offset);
}

static void load_process_stack(struct pt_regs* regs)
{
  char buf[0x1000];
  size_t count = abs(sp_debuggee - regs->uregs[13] + addr_size);

  lseek(mem_file, regs->uregs[13], SEEK_SET);
  read(mem_file, buf, count);

  LOG("from <%08lx-%08lx>\n", regs->uregs[13], regs->uregs[11]);

  lseek(mem_file_own, regs->uregs[13]+sp_offset, SEEK_SET);
  write(mem_file_own, buf, count);

  LOG("to <%08lx-%08lx>\n", regs->uregs[13] + sp_offset, regs->uregs[11] + sp_offset);
}

static void store_process_stack(struct pt_regs* regs)
{
  char buf[0x1000];
  size_t count = abs(sp_debuggee - regs->uregs[13] + addr_size);

  lseek(mem_file_own, regs->uregs[13]+sp_offset, SEEK_SET);
  read(mem_file_own, buf, count);

  LOG("from <%08lx-%08lx>\n", regs->uregs[13] + sp_offset, regs->uregs[11] + sp_offset);

  lseek(mem_file, regs->uregs[13], SEEK_SET);
  write(mem_file, buf, count);

  LOG("to <%08lx-%08lx>\n", regs->uregs[13], regs->uregs[11]);
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
    LOG("Stopping PID %d, TID %d.\n", DIABLO_Debugger_global_state.process_pid, tids[iii]);
    my_tgkill(DIABLO_Debugger_global_state.process_pid, tids[iii], SIGSTOP);
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
      my_tgkill(DIABLO_Debugger_global_state.process_pid, recv, SIGCONT);
      my_tgkill(DIABLO_Debugger_global_state.process_pid, recv, SIGCONT);

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

static void switch_to(uintptr_t id)
{
  /* We assume pointers with value 0 to be invalid, so we can use this as a guard value. Using volatile for clobbered warning -_- */
  volatile uintptr_t dest = 0;

  /* Look up the the destination in the map */
  for(size_t iii = 0; iii < DIABLO_Debugger_nr_of_entries; iii++)
  {
    t_sd_map_entry loop = DIABLO_Debugger_addr_mapping[iii];

    if(loop.key == id)
    {
      LOG("Found value: %"PRIxPTR" and mapping sec: %p\n", loop.value, DIABLO_Debugger_addr_mapping);
      dest = loop.value + (uintptr_t)DIABLO_Debugger_addr_mapping;
      break;
    }
  }

  if(dest != 0)
  {
    LOG("Found the destination: %"PRIxPTR"\n", dest);

    /* We're using a setjmp/longjmp to save/restore all callee-saved registers */
    jmp_buf env;
    if(setjmp(env))
      return;

    ((fun_moved_from_context*) dest)();/* Invoke the destination */
    longjmp(env, 0);
  }
  else
  {
    LOG("Unknown address: application will be forced to shut down!\n");
    close_debugger();
  }
}

static void handle_switch()
{
  struct pt_regs* regs = &DIABLO_Debugger_global_state.regs;/* Use regs variable as pointer to member to avoid more verbose code */

  /* Zero out these fields that might get filled in by the fragment */
  DIABLO_Debugger_global_state.link = 0;
  DIABLO_Debugger_global_state.address = 0;

#ifndef ENABLE_LOGGING
    /* If we're not logging, get the registers now */
    ptrace(PTRACE_GETREGS, DIABLO_Debugger_global_state.recv_pid, NULL, regs);
#endif

    set_stack_pointer(regs->uregs[13]);
    //load_process_stack(&regs);TODO: Re-enable!

    /* Get the constant from the stack and adjust the stack pointer to 'pop' it */
    uintptr_t id = ptrace(PTRACE_PEEKTEXT, DIABLO_Debugger_global_state.recv_pid, (void*)(regs->uregs[13]), NULL);
    regs->uregs[13] += addr_size;

    /* TODO: The FP-register is not always used as frame pointer, in that case we shouldn't adjust it */
    //regs->uregs[11] += sp_offset;
    //regs->uregs[13] += sp_offset;
    switch_to(id);
    //regs->uregs[13] -= sp_offset;
    //regs->uregs[11] -= sp_offset;

    //store_process_stack(&regs);TODO: Re-enable!

    /* Print out the information returned by the fragment we executed */
    LOG("ret addr: %"PRIxPTR"\n", DIABLO_Debugger_global_state.address);
    LOG("ret link: %"PRIxPTR"\n", DIABLO_Debugger_global_state.link);

    /* If a call occurred, update the link register */
    if(DIABLO_Debugger_global_state.link)
      regs->uregs[14] = DIABLO_Debugger_global_state.link;

    /* If we have a destination address, use it. Else just go to the next instruction */
    switch(DIABLO_Debugger_global_state.address)
    {
      case 0:
        regs->uregs[15] += addr_size;
        break;
      case 1:
        regs->uregs[15] = regs->uregs[14];
        break;
      default:
        regs->uregs[15] = DIABLO_Debugger_global_state.address;
    }

    /* Put new register values in place and continue the debuggee */
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
    LOG("Returning to: %lx\n", regs->uregs[15]);
    LOG("Debugger exited\n");

    ptrace(PTRACE_SETREGS, DIABLO_Debugger_global_state.recv_pid, NULL, regs);
}

static void debug_main()
{
  /* Infinite loop, handling signals until the debuggee exits */
  while(true)
  {
    int status, ret;
    struct pt_regs* regs = &DIABLO_Debugger_global_state.regs;/* Use regs variable as pointer to member to avoid more verbose code */

    /* Wait for a signal from the debuggee. We wait for all PIDs (-1), not sure if the __WALL is required though. */
    DIABLO_Debugger_global_state.recv_pid = waitpid(-1, &status, __WALL);
    pid_t recv_pid = DIABLO_Debugger_global_state.recv_pid;

    /* If waitpid does not succeed, the process is already dead */
    if (recv_pid == -1)
    {
      LOG("The debuggee has terminated (waitpid returns -1)\n");
      close_debugger();
    }

    LOG("Debugger entered for PID: %d\n", recv_pid);

#ifdef ENABLE_LOGGING
    /* Get the registers. If logging is enabled, we do this now because so we can log them before potentially exiting */
    ret = ptrace(PTRACE_GETREGS, recv_pid, NULL, regs);
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
      removeThread(recv_pid);
      continue;
    }
    else if (WIFSIGNALED(status))
    {
      LOG("Debuggee has been terminated by a signal with number %d.\n", WTERMSIG(status));

      /* Remove the thread (this might close the debugger if there's no debuggees left) */
      removeThread(recv_pid);
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
            detachFromThreadGroup(recv_pid);

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

              ptrace(PTRACE_LISTEN, recv_pid, NULL, NULL);
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
                ptrace(PTRACE_DETACH, recv_pid, NULL, NULL);

                /* Remove the thread (this might close the debugger if there's no debuggees left) */
                removeThread(recv_pid);
                continue;
              case PTRACE_EVENT_CLONE:
              case PTRACE_EVENT_FORK:
              case PTRACE_EVENT_VFORK:
                {
                  /* If an event happened that resulted in new thread, we should trace it too */
                  pid_t new_pid;
                  ptrace(PTRACE_GETEVENTMSG, recv_pid, 0, &new_pid);
                  ptrace(PTRACE_CONT, new_pid, NULL, NULL);
                  addThread(new_pid);
                  break;
                }
              case PTRACE_EVENT_EXIT:
                ptrace(PTRACE_DETACH, recv_pid, NULL, NULL);
                continue;
              case PTRACE_EVENT_STOP:
                break;
              default:
                handle_switch(recv_pid);
            }

            signal = 0;/* Don't deliver this signal */
            break;
          }
      }

      /* Continue the debuggee and - possibly - deliver signal */
      ptrace(PTRACE_CONT, recv_pid, NULL, (void*) signal);
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
  ptrace(PTRACE_DETACH, debugger_pid, NULL, NULL);
  ANDROID_LOG("Finalization routine. Signaling the mini-debugger to shut down.");
  raise(SIGMINIDEBUGGER);
}

/* The inialization routine that will fork the process. The child becomes the debugger and debugs the parent */
void DIABLO_Debugger_Init()
{
  volatile unsigned long can_run = 0;

  /* Get the parent PID before forking */
  pid_t parent_pid = getpid();
  pid_t child_pid = fork();

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
        /* Set up SIGCHLD ignoring. This means some SIGCHLDs won't even be sent (and presented to the tracer through ptrace-stop) anymore. */
        struct sigaction sa;
        sa.sa_handler = SIG_IGN; //handle signal by ignoring
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction(SIGCHLD, &sa, 0) == -1) {
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

          ANDROID_LOG("Start main loop");
          debug_main();
        }

        close_debugger();
      }
  }

  /* Install the finalization routine to executed when the parent exits */
  atexit(fini_routine);

  /* In the parent, we'll spin on this variable until the child signals we can continue */
  while (!can_run);

  /* Have the parent attach to the mini-debugger */
  debugger_pid = child_pid;
  ptrace(PTRACE_SEIZE, debugger_pid, NULL, NULL);
}

/* For reading we can always use /proc/PID/mem */
static void read_tracee_mem(void* buf, size_t size, uintptr_t addr)
{
  lseek(mem_file, addr, SEEK_SET);
  read(mem_file, buf, size);
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
    ptrace(PTRACE_POKEDATA, DIABLO_Debugger_global_state.recv_pid, (void*)addr, (void*)value);
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
    ptrace(PTRACE_POKEDATA, DIABLO_Debugger_global_state.recv_pid, (void*)addr, (void*)value);
  }
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
