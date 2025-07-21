## COMP0019 CW5 Grade Report

Graded at: 2025-03-27 20:02:26.050145

Graded for revision:  eb19a8fb74f2d54cd49357d847478d2738102b7a

### Output


      CLEAN 
      COMPILE sh0019.c
    sh0019.c: In function ‘handle_sigint’:
    sh0019.c:16:24: warning: unused parameter ‘sig’ [-Wunused-parameter]
       16 | void handle_sigint(int sig) {
          |                    ~~~~^~~
    sh0019.c: In function ‘run_list’:
    sh0019.c:501:14: warning: variable ‘chain_start’ set but not used [-Wunused-but-set-variable]
      501 |     command* chain_start = NULL;
          |              ^~~~~~~~~~~
      COMPILE helpers.c
      LINK sh0019 
    
    Test SIMPLE1: passed
    Test SIMPLE2: passed
    Test SIMPLE3: passed
    Test SIMPLE4: passed
    Test BG1: passed
    Test BG2: passed
    Test BG3: passed
    Test LIST1: passed
    Test LIST2: passed
    Test LIST3: passed
    Test LIST4: passed
    Test LIST5: passed
    Test LIST6: passed
    Test LIST7: passed
    Test LIST8: passed
    Test COND1: passed
    Test COND2: passed
    Test COND3: passed
    Test COND4: passed
    Test COND5: passed
    Test COND6: passed
    Test COND7: passed
    Test COND8: passed
    Test COND9: passed
    Test COND10: passed
    Test COND11: passed
    Test PIPE1: passed
    Test PIPE2: passed
    Test PIPE3: passed
    Test PIPE4: passed
    Test PIPE5: passed
    Test PIPE6: passed
    Test PIPE7: passed
    Test PIPE8: passed
    Test PIPE9: passed
    Test PIPE10: passed
    Test PIPE11: passed
    Test PIPE12: passed
    Test PIPE13: passed
    Test PIPE14: passed
    Test PIPE15: passed
    Test PIPE16: passed
    Test PIPE17: passed
    Test PIPE18: passed
    Test PIPE19: passed
    Test PIPE20: passed
    Test PIPE21: passed
    Test PIPE22: passed
    Test PIPE23: passed
    Test ZOMBIE1: passed
    Test ZOMBIE2: FAILED in 0.901 sec
        command  `sleep 0.05 & sleep 0.05 & sleep 0.05 & sleep 0.05 & \n sleep 0.07 \n sleep 0.07 \n ps T`
      output file size 1280, expected <= 1000
    Test REDIR1: passed
    Test REDIR2: passed
    Test REDIR3: passed
    Test REDIR4: passed
    Test REDIR5: passed
    Test REDIR6: passed
    Test REDIR7: passed
    Test REDIR8: passed
    Test REDIR9: passed
    Test REDIR10: passed
    Test REDIR11: passed
    Test REDIR12: passed
    Test REDIR13: passed
    Test REDIR14: passed
    Test REDIR15: passed
    Test REDIR16: passed
    Test INTR1: passed
    Test INTR2: passed
    Test INTR3: passed
    Test INTR4: passed
    Test INTR5: passed
    Test CD1: passed
    Test CD2: passed
    Test CD3: passed
    Test CD4: passed
    Test CD5: passed
    Test CD6: passed
    Test CD7: passed
    Test CD8: passed
    Test ADVPIPE1: passed
    Test ADVBGCOND1: passed
    Test ADVBGCOND2: passed
    
    82 of 83 tests passed


### Marking

Total score: (99/100)

