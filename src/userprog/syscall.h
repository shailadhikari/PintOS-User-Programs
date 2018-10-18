#include "threads/thread.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct file_metadata
{
  int inode_id;
  struct file *file_desc;
  struct list_elem file_elem;
};

void syscall_init (void);
struct file_metadata* retrieve_file_data(int inode_id);

#endif /* userprog/syscall.h */
