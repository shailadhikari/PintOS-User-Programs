#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
   static int
   get_user (const uint8_t *uaddr)
   {
     if(!is_user_vaddr(uaddr))
     {
       thread_exit(-1);
       return -1;
     }
     int result;
     asm ("movl $1f, %0; movzbl %1, %0; 1:"
          : "=&a" (result) : "m" (*uaddr));
     return result;
   }
   
   /* Writes BYTE to user address UDST.
      UDST must be below PHYS_BASE.
      Returns true if successful, false if a segfault occurred. */
   static bool
   put_user (uint8_t *udst, uint8_t byte)
   {
     if(!is_user_vaddr(udst))
       return false;
     int error_code;
     asm ("movl $1f, %0; movb %b2, %1; 1:"
          : "=&a" (error_code), "=m" (*udst) : "q" (byte));
     return error_code != -1;
   }
   
   struct file_metadata* retrieve_file_data(int inode_id)
   {
     struct list_elem *fetch_elem = list_begin (&thread_current()->file_list);
     while(fetch_elem != list_end(&thread_current()->file_list))
     {
       if(list_entry(fetch_elem, struct file_metadata, file_elem)->inode_id == inode_id)
         return list_entry(fetch_elem, struct file_metadata, file_elem);
       fetch_elem = list_next(fetch_elem);
     }
     return NULL;
   }
   
   static bool is_Valid(void * esp)
   {
     if(esp >= PHYS_BASE)
     {
       thread_exit(-1);
       return false;
     }
     
     uint8_t *firstByte = (uint8_t *)esp;
   
     if(get_user(firstByte) == -1 || get_user(firstByte + 1) == -1 || get_user(firstByte + 2) == -1 || get_user(firstByte + 3) == -1)
     {
       thread_exit(-1);
       return false;
     }
     return true;
   }
   
   static int get_bytes_from_addr(void * esp)
   {
     uint8_t *firstByte = (uint8_t *)esp;
     int output;
     output = (get_user(firstByte) << 0) + (get_user(firstByte + 1) << 8) + (get_user(firstByte + 2) << 16) + (get_user(firstByte + 3) << 24);
     return output;
   }
   
   static bool is_valid_char_address(void * addr)
   {
     for(int mem = get_user((uint8_t*)addr); mem != -1;)
     {
       if(mem == -1)
         return false;
       if(mem == '\0')
         return true;
       mem = get_user((uint8_t*)addr++);
     }
     return false;
   }
   
   system_call_filesize(int inode_id, struct intr_frame *f)
   {
     struct file_metadata *file_metadata = retrieve_file_data(inode_id);
     if (file_metadata != NULL){
       f->eax = file_length(file_metadata->file_desc);
     }
   }
   
   void system_call_seek(int inode_id, unsigned position)
   {  
     struct file_metadata *file_metadata = retrieve_file_data(inode_id);
     if (file_metadata != NULL){
       file_seek(file_metadata->file_desc, position);
     }
   }
   
   void system_call_tell(int inode_id, struct intr_frame *f)
   {
     struct file_metadata *file_metadata = retrieve_file_data(inode_id);
     if(file_metadata != NULL)
       f->eax = file_tell(file_metadata->file_desc);
     free(file_metadata);
   }
   
   void system_call_create(const char * file, unsigned initial_size, struct intr_frame *f)
   {
     if(!is_valid_char_address(file))
       thread_exit(-1);
     else 
       f->eax = filesys_create(file, initial_size);
   }
   
   void system_call_remove(const char *file, struct intr_frame *f)
   {
     if(!is_valid_char_address(file))
       thread_exit(-1);
     else 
       f->eax = filesys_remove(file);
   }
   
   int propen(const char *file_name)
   {
     struct file * fr = filesys_open(file_name);
     if(fr == NULL)
     {
       return -1;
     }
     struct file_metadata *file_metadata = malloc (sizeof(struct file_metadata));
     if(file_metadata == NULL)
     {
       return -1;
     }

    int inode_id = thread_current()->inode_id++;
    file_metadata->inode_id = inode_id;
    file_metadata->file_desc = fr;
    list_push_back(&thread_current()->file_list, &file_metadata->file_elem);
    return file_metadata->inode_id;
   }
   
   static int system_call_open(struct intr_frame *f)
   {
     char *file_name = *(char **)(f->esp + 4);
     f->eax = propen(file_name);
     return 0;
   }
   
   void system_call_close(int inode_id)
   {  
     struct file_metadata *file_metadata = retrieve_file_data(inode_id);
     if(file_metadata != NULL)
     {
       file_close(file_metadata->file_desc);
       list_remove(&file_metadata->file_elem);
       free(file_metadata);
     }
   }
   
   static int system_call_exit(struct intr_frame *f)
   {
     return get_bytes_from_addr(f->esp + 4);
   }
   
   static void system_call_halt(struct  intr_frame *f UNUSED)
   {
     shutdown();
   }
   
   static int system_call_wait(int pid)
   {
     return process_wait(pid);
   }
   
   void system_call_exec(const char *cmd_line, struct intr_frame *f)
   {
     if(!is_valid_char_address(cmd_line))
       thread_exit(-1);
     else{
       f->eax = process_execute (cmd_line, false);
       // thread_exit(0);
     }
   }
   
   void system_call_write(int inode_id, const void *buffer, unsigned size, struct intr_frame *f)
   {
     //printf("HELLO1\n");
     if(inode_id == 1)
     {
       putbuf((char *)buffer, (size_t)size);
       f->eax = size;
     }
     else
     {
       struct file_metadata *file_metadata = retrieve_file_data(inode_id);
       if(file_metadata != NULL)
         f->eax = file_write(file_metadata->file_desc, buffer, size);
       else 
         thread_exit(-1);
     }
   }
   
   void system_call_read(int inode_id, const void *buffer, unsigned size, struct intr_frame *f)
   {
       struct file_metadata *file_metadata = retrieve_file_data(inode_id);
       if(file_metadata != NULL)
         f->eax = file_read(file_metadata->file_desc, buffer, size);
       else 
         thread_exit(-1);
   }
   
   
   static void syscall_handler (struct intr_frame *f)
   { 
     if (!is_Valid(f->esp)){
       //thread_exit(-1);
       return;
     } 
     else 
     {
       int result;
       int sys_call_type = *(uint32_t *)f->esp;
       switch(sys_call_type)
       {
         case SYS_HALT:
           system_call_halt(f);
           break;
         
         case SYS_EXIT:
           if(!is_Valid(f->esp + 4))
             thread_exit(-1);
           else
             thread_exit(system_call_exit(f));
           break;
         
         case SYS_EXEC:
           if(!is_Valid(f->esp + 4))
             thread_exit(-1);
           else
             system_call_exec((const char *)get_bytes_from_addr(f->esp + 4), f);
           break;
         
         case SYS_WAIT:
           if(!is_Valid(f->esp + 4))
             thread_exit(-1);
           else
             f->eax = system_call_wait(get_bytes_from_addr(f->esp + 4));
           break;
         
         case SYS_CREATE:
           if(!is_Valid(f->esp + 4) || !is_Valid(f->esp + 8))
             thread_exit(-1);
           else 
           {
             const char *file = get_bytes_from_addr(f->esp + 4);
             unsigned initial_size = (unsigned) get_bytes_from_addr(f->esp + 8);
             if(file + initial_size - 1 >= PHYS_BASE || !is_Valid(file + initial_size - 1))
               thread_exit(-1);
             else
               system_call_create(file, initial_size, f);
           }
           break;
         
         case SYS_REMOVE:
           if(!is_Valid(f->esp + 4))
             thread_exit(-1);
           else
             system_call_remove((const char *)get_bytes_from_addr(f->esp + 4), f);
           break;
   
         case SYS_OPEN:
           if(!is_Valid(f->esp + 4))
             thread_exit(-1);
           else if(!is_valid_char_address(*(char **)(f->esp + 4))){
              thread_exit(-1);
           }
           else
           {
            result = system_call_open(f);
           }
           break;
         
         case SYS_FILESIZE:
           if(!is_Valid(f->esp + 4))
             thread_exit(-1);
           else
             system_call_filesize(get_bytes_from_addr(f->esp + 4), f);
           break;
         
         case SYS_READ:
           if(!is_Valid(f->esp + 4) || !is_Valid(f->esp + 8) || !is_Valid(f->esp + 12))
             thread_exit(-1);
           else 
           {
             int inode_id = get_bytes_from_addr(f->esp + 4);
             const void *buffer = (const void *) get_bytes_from_addr(f->esp + 8);
             unsigned size = (unsigned) get_bytes_from_addr(f->esp + 12);
             if(buffer + size - 1 >= PHYS_BASE || !is_Valid(buffer + size - 1))
               thread_exit(-1);
             else
               system_call_read(inode_id, buffer, size, f);
           }
           break;
   
         case SYS_WRITE:
           if(!is_Valid(f->esp + 4) || !is_Valid(f->esp + 8) || !is_Valid(f->esp + 12))
             thread_exit(-1);
           else 
           {
             int inode_id = get_bytes_from_addr(f->esp + 4);
             const void *buffer = (const void *) get_bytes_from_addr(f->esp + 8);
             unsigned size = (unsigned) get_bytes_from_addr(f->esp + 12);
             if(buffer + size - 1 >= PHYS_BASE || !is_Valid(buffer + size - 1))
               thread_exit(-1);
             else
               system_call_write(inode_id, buffer, size, f);
           }
           break;
         
         case SYS_SEEK:
           if(!is_Valid(f->esp + 4) || !is_Valid(f->esp + 8))
             thread_exit(-1);
           else 
           {
             int inode_id = get_bytes_from_addr(f->esp + 4);
             unsigned position = (unsigned) get_bytes_from_addr(f->esp + 8);
             system_call_seek(inode_id, position);
           }
           break;
         
         case SYS_TELL:
         if(!is_Valid(f->esp + 4))
           thread_exit(-1);
         else
           system_call_tell(get_bytes_from_addr(f->esp + 4), f);
         break;
   
         case SYS_CLOSE:
         if(!is_Valid(f->esp + 4))
           thread_exit(-1);
         else
           system_call_close(get_bytes_from_addr(f->esp + 4));
         break;
         
         default:
           break;
       }
       if(result == -1)
         thread_exit(-1);
     }
   }
   
   void syscall_init (void)
   {
     intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
   }
