#include "sh0019.h"
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>  
#include <errno.h> 

// variable to track if SIGINT was received
volatile sig_atomic_t got_sigint = 0;

// Signal handler for SIGINT 
void handle_sigint(int sig) {
    got_sigint = 1;
}

// change so i can late submit
// struct command
//    Data structure describing a command. Add your own stuff.

typedef struct command command;
struct command {
    int argc;      // number of arguments
    char** argv;   // arguments, terminated by NULL
    pid_t pid;     // process ID running this command, -1 if none
    int background; 
    command* next; // next command in the list
    int operator;  // operator connecting to next command (TOKEN_SEQUENCE, TOKEN_BACKGROUND, etc.)
    int input_fd;  // input file descriptor
    int output_fd; // output file descriptor
    int error_fd;  // error file descriptor
    
    // Redirection information
    char* stdin_file;  // filename for stdin redirection
    char* stdout_file; // filename for stdout redirection
    char* stderr_file; // filename for stderr redirection
};


// command_alloc()
//    Allocate and return a new command structure.

static command* command_alloc(void) {
    command* c = (command*) malloc(sizeof(command));
    c->argc = 0;
    c->argv = NULL;
    c->pid = -1;
    // flag for background 
    c->background = 0;
    c->next = NULL; 
    c->operator = 0;
    // default to stdin/stout
    c->input_fd = 0; 
    c->output_fd = 1;
    c->error_fd = 2;
    
    c->stdin_file = NULL;
    c->stdout_file = NULL;
    c->stderr_file = NULL;
    return c;
}


// command_free(c)
//    Free command structure `c`, including all its words.

static void command_free(command* c) {
    for (int i = 0; i < c->argc; ++i) {
        free(c->argv[i]);
    }
    free(c->argv);
    
    // free redirection filenames
    if (c->stdin_file) free(c->stdin_file);
    if (c->stdout_file) free(c->stdout_file);
    if (c->stderr_file) free(c->stderr_file);
    
    free(c);
}


// command_append_arg(c, word)
//    Add `word` as an argument to command `c`. This increments `c->argc`
//    and augments `c->argv`.

static void command_append_arg(command* c, char* word) {
    c->argv = (char**) realloc(c->argv, sizeof(char*) * (c->argc + 2));
    c->argv[c->argc] = word;
    c->argv[c->argc + 1] = NULL;
    ++c->argc;
}


// COMMAND EVALUATION

// start_command(c, pgid)
//    Start the single command indicated by `c`. Sets `c->pid` to the child
//    process running the command, and returns `c->pid`.
//
//    PART 1: Fork a child process and run the command using `execvp`.
//    PART 5: Set up a pipeline if appropriate. This may require creating a
//       new pipe (`pipe` system call), and/or replacing the child process's
//       standard input/output with parts of the pipe (`dup2` and `close`).
//       Draw pictures!
//    PART 7: Handle redirections.
//    PART 8: The child process should be in the process group `pgid`, or
//       its own process group (if `pgid == 0`). To avoid race conditions,
//       this will require TWO calls to `setpgid`.



// start_command() just prints erorr, doesnt start command
// run_list -> calls start_command
pid_t start_command(command* c, pid_t pgid) {
    // each command needs to know about stdin/stdout pipes
    // default to stdin/stdout
    int pipefd[2] = {0, 1}; 
    if (c->input_fd != 0) {
        // use provided input file descriptor
        pipefd[0] = c->input_fd; 
    }
    if (c->output_fd != 1) {
        // use provided output file descriptor
        pipefd[1] = c->output_fd; 
    }
    
    // fork child process
    // -1 w fork failure, 0 for child process, else parent process
    // we now have 2 proccesses with identical memory
    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork");
        exit(1);
    }

    // exec in child
    if (child_pid == 0) {
        // set process group - child sets its own process group
        if (pgid == 0) pgid = getpid();
        setpgid(0, pgid);
        
        // Handle input redirection from file
        if (c->stdin_file != NULL) {
            int fd = open(c->stdin_file, O_RDONLY);
            if (fd == -1) {
                fprintf(stderr, "%s: %s\n", c->stdin_file, strerror(errno));
                exit(1);
            }
            if (dup2(fd, 0) == -1) {
                perror("dup2 stdin file");
                exit(1);
            }
            close(fd);
        }
        // redirect stdin from pipe if needed
        else if (pipefd[0] != 0) {
            if (dup2(pipefd[0], 0) == -1) {
                perror("dup2 stdin");
                exit(1);
            }
            close(pipefd[0]); 
        }
        
        // handle output redirection to file 
        if (c->stdout_file != NULL) {
            int fd = open(c->stdout_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd == -1) {
                fprintf(stderr, "%s: %s\n", c->stdout_file, strerror(errno));
                exit(1);
            }
            if (dup2(fd, 1) == -1) {
                perror("dup2 stdout file");
                exit(1);
            }
            close(fd);
        }
        else if (pipefd[1] != 1) {
            if (dup2(pipefd[1], 1) == -1) {
                perror("dup2 stdout");
                exit(1);
            }
            close(pipefd[1]);
        }
        
        // handle error redirection
        if (c->stderr_file != NULL) {
            int fd = open(c->stderr_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd == -1) {
                fprintf(stderr, "%s: %s\n", c->stderr_file, strerror(errno));
                exit(1);
            }
            if (dup2(fd, 2) == -1) {
                perror("dup2 stderr file");
                exit(1);
            }
            close(fd);
        }
        
        // set process group
        setpgid(0, pgid ? pgid : getpid());
        
        // execvp replaces curr process image with new prgram, 
        // so pid wont change, but process memory is replaced;
        // stack reset, heap reset; therefore if 
        // it returns it must have failed
        if(execvp(c->argv[0], c->argv) == -1) {
            fprintf(stderr, "%s: %s\n", c->argv[0], strerror(errno));
            exit(1);
        }
    }

    // excecute this in parent
    else {
        // store child pid
        c->pid = child_pid;
        
        // set process group in parent too - avoids race condition
        if (pgid == 0) pgid = child_pid;
        setpgid(child_pid, pgid);
        
        // close pipe file descriptors in parent process
        if (pipefd[0] != 0) {
            close(pipefd[0]);
        }
        if (pipefd[1] != 1) {
            close(pipefd[1]);
        }
    }
    
    return c->pid;
}

// run_list(c)
//    Run the command list starting at `c`.
//
//    PART 1: Start the single command `c` with `start_command`,
//        and wait for it to finish using `waitpid`.
//    The remaining parts may require that you change `struct command`
//    (e.g., to track whether a command is in the background)
//    and write code in run_list (or in helper functions!).
//    PART 2: Treat background commands differently.
//    PART 3: Introduce a loop to run all commands in the list.
//    PART 4: Change the loop to handle conditionals.
//    PART 5: Change the loop to handle pipelines. Start all processes in
//       the pipeline in parallel. The status of a pipeline is the status of
//       its LAST command.
//    PART 8: - Choose a process group for each pipeline.
//       - Call `claim_foreground(pgid)` before waiting for the pipeline.
//       - Call `claim_foreground(0)` once the pipeline is complete.



// stage4 -> &&: run the second command only if the first one succeeds (exit status 0)
// ||: run the command only if the first one fails (exit status non-zero)

// execute command and get status
int execute_command(command* cmd, int wait_for_completion) {

    // special case for cd
    if (cmd->argc > 0 && strcmp(cmd->argv[0], "cd") == 0) {
        // save original standard file descriptors
        int saved_stdout = dup(STDOUT_FILENO);
        int saved_stderr = dup(STDERR_FILENO);
        int fd_out = STDOUT_FILENO;
        int fd_err = STDERR_FILENO;
        
        // setup redirections if specified
        if (cmd->stdout_file != NULL) {
            fd_out = open(cmd->stdout_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd_out != -1) {
                dup2(fd_out, STDOUT_FILENO);
                close(fd_out);
            }
        }
        
        if (cmd->stderr_file != NULL) {
            fd_err = open(cmd->stderr_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd_err != -1) {
                dup2(fd_err, STDERR_FILENO);
                close(fd_err);
            }
        }
        
        // default to HOME directory
        const char* dir = cmd->argc > 1 ? cmd->argv[1] : getenv("HOME");
        int result = 0;
        
        if (chdir(dir) == -1) {
            // error message if chdir fails
            fprintf(stderr, "cd: %s: %s\n", dir, strerror(errno));
            result = 1;
        }
        
        // restore original standard file descriptors
        dup2(saved_stdout, STDOUT_FILENO);
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stdout);
        close(saved_stderr);
        
        return result;
    }
    
    // normal command execution
    pid_t pid = start_command(cmd, 0);
    if (pid <= 0) {
        //error starting command
        return 1; 
    }
    
    if (!wait_for_completion) {
        // bg command, assume successs
        return 0;
    }
    
    // give terminal control to the command's process group
    claim_foreground(pid);
    
    int status;
    waitpid(pid, &status, 0);
    
    // return terminal control to shell
    claim_foreground(0);
    
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else {
        // command terminated abnormally
        return 1; 
    }
}

// helper to run a chain of commands with conditionals
int run_command_chain(command* start, command* end) {
    int chain_status = 0;
    command* chain_prev = NULL;
    command* chain_cmd = start;
    
    while (chain_cmd != end) {
        // if no args, skip
        if (chain_cmd->argc == 0) {
            chain_cmd = chain_cmd->next;
            continue;
        }
        
        // chekc if we should run based on conditionals
        int chain_should_run = 1;
        
        if (chain_prev != NULL) {
            if (chain_prev->operator == TOKEN_AND) {
                chain_should_run = (chain_status == 0);
            } else if (chain_prev->operator == TOKEN_OR) {
                chain_should_run = (chain_status != 0);
            }
        }
        
        if (chain_should_run) {
            // always wait for commands in a chain
            chain_status = execute_command(chain_cmd, 1);
        }
        
        chain_prev = chain_cmd;
        chain_cmd = chain_cmd->next;
    }
    
    return chain_status;
}

// running a pipeline
int run_pipeline(command* start, command* end, int background) {
    command* curr = start;
    int prev_pipe_read = -1;
    pid_t* pids = NULL;
    int pid_count = 0;
    
    // count commands in pipeline
    command* count_cmd = start;
    while (count_cmd != end) {
        if (count_cmd->argc > 0) {
            pid_count++;
        }
        count_cmd = count_cmd->next;
    }
    
    // alloc array to track PIDs
    // wait for all processes in pipeline to finish to avoid zombies
    // also use so we know which process is the last one
    pids = (pid_t*)malloc(sizeof(pid_t) * pid_count);
    int pid_index = 0;
    
    // first process becomes process group leader
    pid_t pipeline_pgid = 0;
    
    while (curr != end) {
        if (curr->argc == 0) {
            curr = curr->next;
            continue;
        }
        
        // create pipe for the next command in pipeline
        // default to stdin/stdout
        int pipefd[2] = {0, 1}; 
        
        // if this isnt the last 
        // command in pipeline, create a pipe
        if (curr->operator == TOKEN_PIPE) {
            if (pipe(pipefd) == -1) {
                perror("pipe");
                exit(1);
            }
        }
        
        // set up input from previous command's pipe
        if (prev_pipe_read != -1) {
            curr->input_fd = prev_pipe_read;
        }
        
        // set up output to next command's pipe
        // set output_fd to the write end of the new pipe
        // store read end of that pipe for the next command to use
        if (curr->operator == TOKEN_PIPE) {
            curr->output_fd = pipefd[1];
            prev_pipe_read = pipefd[0];
        } else {
            // no more piping
            prev_pipe_read = -1; 
        }
        
        pid_t cmd_pid = start_command(curr, pipeline_pgid);
        if (cmd_pid > 0) {
            pids[pid_index++] = cmd_pid;
            
            // save the first process's PID as the process group ID
            if (pipeline_pgid == 0) {
                pipeline_pgid = cmd_pid;
            }
        }
        
        curr = curr->next;
    }
    
    // background pipelines, don't wait
    if (background) {
        free(pids);
        return 0;
    }
    
    // give terminal control to pipeline process group
    claim_foreground(pipeline_pgid);
    
    // wait for all processes in pipeline to finish (not just the last one)
    int status = 0;
    
    // first, wait for the last process in the pipeline
    if (pid_count > 0) {
        pid_t last_pid = pids[pid_count - 1];
        waitpid(last_pid, &status, 0);
        
        // then terminate all other processes in the pipeline
        for (int i = 0; i < pid_count - 1; i++) {
            // Send SIGTERM to each process
            kill(pids[i], SIGTERM);
            // Reap it without blocking
            waitpid(pids[i], NULL, 0);
        }
    }
    
    // return terminal control to shell
    claim_foreground(0);
    
    free(pids);
    
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else {
        return 1;
    }
}

// determine if command starts a pipeline
int starts_pipeline(command* c) {
    return (c != NULL && c->argc > 0 && c->operator == TOKEN_PIPE);
}

// find the end of a pipeline
command* find_pipeline_end(command* start) {
    command* curr = start;
    while (curr != NULL && curr->operator == TOKEN_PIPE) {
        curr = curr->next;
    }
    return curr ? curr->next : NULL;
}

void run_list(command* c) {
    int prev_status = 0; 
    command* prev_cmd = NULL;
    // track start of a conditional chain 
    command* chain_start = NULL;
    
    while (c) {
        // only exec if we have args
        if (c->argc == 0) {
            c = c->next;
            continue;
        }
        
        // start of a new conditional chain
        if (prev_cmd == NULL || prev_cmd->operator == TOKEN_SEQUENCE || 
            prev_cmd->operator == TOKEN_BACKGROUND) {
            chain_start = c;
        }
        
        int should_run = 1; 
        
        // check the previous command's operator to decide if we should run this one
        if (prev_cmd != NULL) {
            if (prev_cmd->operator == TOKEN_AND) {
                // For &&, only run if previous command succeeded (status 0)
                should_run = (prev_status == 0);
            } else if (prev_cmd->operator == TOKEN_OR) {
                // For ||, only run if previous command failed (status non-zero)
                should_run = (prev_status != 0);
            }
        }
        
        // find the end of this segment (ended by ; or &)
        command* segment_end = c;
        while (segment_end && 
               segment_end->operator != TOKEN_SEQUENCE && 
               segment_end->operator != TOKEN_BACKGROUND) {
            segment_end = segment_end->next;
        }
        
        // check if this segment ends with background
        int run_in_background = 0;
        if (segment_end && segment_end->operator == TOKEN_BACKGROUND) {
            run_in_background = 1;
        }
        
        if (should_run) {
            if (c->operator == TOKEN_PIPE) {
                // find the end of the pipeline
                command* pipeline_end = c;
                while (pipeline_end && pipeline_end->operator == TOKEN_PIPE) {
                    pipeline_end = pipeline_end->next;
                }
                
                if (pipeline_end) {
                    if (run_in_background) {
                        pid_t bg_pipe_pid = fork();
                        
                        if (bg_pipe_pid == 0) {
                            // child process runs pipeline
                            run_pipeline(c, pipeline_end->next, 0);
                            exit(0);
                        } else if (bg_pipe_pid > 0) {
                            // parent process continues immediately
                            prev_status = 0;
                        }
                    } else {
                        // foreground pipeline
                        prev_status = run_pipeline(c, pipeline_end->next, 0);
                    }
                    
                    // move to command after pipeline
                    prev_cmd = pipeline_end;
                    c = pipeline_end->next;
                    continue;
                }
            }
            
            // handle background chains
            if (run_in_background) {
                pid_t bg_pid = fork();
                
                if (bg_pid == 0) {
                    // child process to execute background command
                    // We need to set our own process group
                    setpgid(0, 0);
                    
                    if (c->operator == TOKEN_AND || c->operator == TOKEN_OR) {
                        // conditional chain
                        exit(run_command_chain(c, segment_end->next));
                    } else {
                        // single command in background
                        exit(execute_command(c, 1)); 
                    }
                } else if (bg_pid > 0) {
                    // par process continues 
                    // intr3
                    // give the background process a chance to start
                    usleep(10000);
                    
                    prev_status = 0;
                    c = segment_end->next; // skip to next command after &
                    prev_cmd = segment_end;
                    continue;
                }
            } else {
                // foreground command
                if (c->operator == TOKEN_AND || c->operator == TOKEN_OR) {
                    prev_status = run_command_chain(c, segment_end ? segment_end->next : NULL);
                    c = segment_end ? segment_end->next : NULL;
                    prev_cmd = segment_end;
                    continue;
                } else {
                    // execute single command
                    prev_status = execute_command(c, 1);
                }
            }
        }
        
        prev_cmd = c;
        c = c->next;
    }
}


// eval_line(c)
// Parse the command list in `s` and run it via `run_list`.

void eval_line(const char* s) {
    int type;
    char* token;
    
    // Build the first command
    command* first_cmd = command_alloc();
    command* current_cmd = first_cmd;

    // track if we've seen a redirection operator
    int next_is_redirection_file = 0;
    int redirection_type = 0;
    
    // For each string, set type to what kind of token it is
    // and token to the actual string
    while ((s = parse_shell_token(s, &type, &token)) != NULL) {

        if (type == TOKEN_REDIRECTION) {
            next_is_redirection_file = 1;
            redirection_type = token[0];
            if (token[0] == '2' && token[1] == '>') {
                // code for stderr redirection
                redirection_type = '2';
            }
            free(token);
            continue;
        }
        
        // this token is a filename for redirection
        if (next_is_redirection_file) {
            next_is_redirection_file = 0;
            
            // store the filename based on redirection type
            if (redirection_type == '<') {
                current_cmd->stdin_file = token;
            } else if (redirection_type == '>') {
                current_cmd->stdout_file = token;
            } else if (redirection_type == '2') {
                current_cmd->stderr_file = token;
            } else {
                //free token to avoid leak
                free(token);
            }
            continue;
        }
        
        // handling for control operators
        if (type == TOKEN_SEQUENCE || type == TOKEN_BACKGROUND || 
            type == TOKEN_AND || type == TOKEN_OR || type == TOKEN_PIPE) {
            
            if (current_cmd->argc > 0) {
                current_cmd->operator = type;
                
                if (type == TOKEN_BACKGROUND) {
                    current_cmd->background = 1;
                }
                
                // create a new command for the next segment
                current_cmd->next = command_alloc();
                current_cmd = current_cmd->next;
            }
            // only need the type, not the token
            // avoid segmentation faults
            free(token);
        } else {
            // store token in argv array
            // free these later in command_free
            command_append_arg(current_cmd, token);
        }
    }
    
    // Run the command list if we have 
    // at least one command with arguments
    if (first_cmd->argc > 0) {
        run_list(first_cmd);
    }
    
    // free all commands
    command* cmd = first_cmd;
    while (cmd) {
        command* next = cmd->next;
        command_free(cmd);
        cmd = next;
    }
}


int main(int argc, char* argv[]) {
    FILE* command_file = stdin;
    int quiet = 0;

    // Check for '-q' option: be quiet (print no prompts)
    if (argc > 1 && strcmp(argv[1], "-q") == 0) {
        quiet = 1;
        --argc, ++argv;
    }

    // Check for filename option: read commands from file
    if (argc > 1) {
        command_file = fopen(argv[1], "rb");
        if (!command_file) {
            perror(argv[1]);
            exit(1);
        }
    }

    // - Put the shell into the foreground
    // - Ignore the SIGTTOU signal, which is sent when the shell is put back
    //   into the foreground
    claim_foreground(0);
    set_signal_handler(SIGTTOU, SIG_IGN);

    // set up signal handler for SIGINT
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    char buf[BUFSIZ];
    int bufpos = 0;
    int needprompt = 1;

    while (!feof(command_file)) {
        // reap zombies at the beginning of each loop
        pid_t zombie_pid;
        int zombie_status;
        while ((zombie_pid = waitpid(-1, &zombie_status, WNOHANG)) > 0) {
            // Successfully reaped a zombie
        }
        
        // Check if we got interrupted
        if (got_sigint) {
            // reset the flag
            got_sigint = 0;
            
            // clear current line, show a new prompt
            bufpos = 0;
            needprompt = 1;
            printf("\n");
            continue;
        }

        // Print the prompt at the beginning of the line
        if (needprompt && !quiet) {
            printf("sh0019[%d]$ ", getpid());
            fflush(stdout);
            needprompt = 0;
        }

        // Read a string, checking for error or EOF
        if (fgets(&buf[bufpos], BUFSIZ - bufpos, command_file) == NULL) {
            if (ferror(command_file) && errno == EINTR) {
                // ignore EINTR errors
                clearerr(command_file);
                buf[bufpos] = 0;
            } else {
                if (ferror(command_file)) {
                    perror("sh0019");
                }
                break;
            }
        }

        // If a complete command line has been provided, run it
        bufpos = strlen(buf);
        if (bufpos == BUFSIZ - 1 || (bufpos > 0 && buf[bufpos - 1] == '\n')) {
            eval_line(buf);
            bufpos = 0;
            needprompt = 1;
            
        }
    }

    return 0;
}
