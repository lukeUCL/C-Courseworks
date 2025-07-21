# Systems Coursework Portfolio

## Coursework 1 – Dynamic Memory Checker

Implemented a custom dynamic memory allocator with debugging support:  
- Allocation Tracking: Maintains metadata for all active allocations to detect leaks and invalid frees.  
- Error Detection: Identifies wild writes (via canary values), double frees, and pointer misuse.  
- Statistics Reporting: Tracks live/total allocations, failures, and heap size.  
- Leak & Heavy Hitter Reports: Highlights unfreed allocations and code locations responsible for significant memory usage.

---

## Coursework 2 – Virtual Memory (WeensyOS Extension)

Extended a teaching OS to support basic virtual memory:  
- Kernel Memory Isolation: Prevented user access to kernel memory space.  
- Per-Process Address Spaces: Assigned each process its own page table.  
- Virtual Page Allocation: Dynamically mapped free physical pages to requested virtual addresses.  
- Shared Virtual Layouts: Allowed common virtual address ranges across processes for stack and heap.  
- Process Forking: Implemented fork() to clone process memory spaces.

---

## Coursework 3 – Custom Unix Shell

Developed a command-line shell replicating core Unix shell behaviors:  
- Command Execution: Supports built-in commands (cd), foreground, and background tasks.  
- Pipelines & Redirection: Implements piping and file redirection for stdin, stdout, and stderr.  
- Control Operators: Parses and executes command chains using ;, &&, ||, and &.  
- Process Management: Handles process groups, zombie reaping, and terminal control.  
- Signal Handling: Cleanly handles interrupts (e.g., Ctrl+C / SIGINT).
