#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name, bool check);
int process_wait (tid_t);
void process_exit (int state);
void process_activate (void);

#endif /* userprog/process.h */
