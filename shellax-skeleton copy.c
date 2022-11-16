#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h> // termios, TCSANOW, ECHO, ICANON
#include <unistd.h>
#include <fcntl.h>
const char *sysname = "shellax";
#define MAX_STRING_LENGTH 256
#define BUFF_SIZE 1000


enum return_codes {
  SUCCESS = 0,
  EXIT = 1,
  UNKNOWN = 2,
};

struct command_t {
  char *name;
  bool background;
  bool auto_complete;
  int arg_count;
  char **args;
  char *redirects[3];     // in/out redirection
  struct command_t *next; // for piping
};


struct dictionary_t{
    char* key;
    int value;
    struct dictionary_t *next;
};


/**
 * Prints a command struct
 * @param struct command_t *
 */
void print_command(struct command_t *command) {
  int i = 0;
  printf("Command: <%s>\n", command->name);
  printf("\tIs Background: %s\n", command->background ? "yes" : "no");
  printf("\tNeeds Auto-complete: %s\n", command->auto_complete ? "yes" : "no");
  printf("\tRedirects:\n");
  for (i = 0; i < 3; i++)
    printf("\t\t%d: %s\n", i,
           command->redirects[i] ? command->redirects[i] : "N/A");
  printf("\tArguments (%d):\n", command->arg_count);
  for (i = 0; i < command->arg_count; ++i)
    printf("\t\tArg %d: %s\n", i, command->args[i]);
  if (command->next) {
    printf("\tPiped to:\n");
    print_command(command->next);
  }
}
/**
 * Release allocated memory of a command
 * @param  command [description]
 * @return         [description]
 */
int free_command(struct command_t *command) {
  if (command->arg_count) {
    for (int i = 0; i < command->arg_count; ++i)
      free(command->args[i]);
    free(command->args);
  }
  for (int i = 0; i < 3; ++i)
    if (command->redirects[i])
      free(command->redirects[i]);
  if (command->next) {
    free_command(command->next);
    command->next = NULL;
  }
  free(command->name);
  free(command);
  return 0;
}
/**
 * Show the command prompt
 * @return [description]
 */
int show_prompt() {
  char cwd[1024], hostname[1024];
  gethostname(hostname, sizeof(hostname));
  getcwd(cwd, sizeof(cwd));
  printf("%s@%s:%s %s$ ", getenv("USER"), hostname, cwd, sysname);
  return 0;
}
/**
 * Parse a command string into a command struct
 * @param  buf     [description]
 * @param  command [description]
 * @return         0
 */
int parse_command(char *buf, struct command_t *command) {
  const char *splitters = " \t"; // split at whitespace
  int index, len;
  len = strlen(buf);
  while (len > 0 && strchr(splitters, buf[0]) != NULL) // trim left whitespace
  {
    buf++;
    len--;
  }
  while (len > 0 && strchr(splitters, buf[len - 1]) != NULL)
    buf[--len] = 0; // trim right whitespace

  if (len > 0 && buf[len - 1] == '?') // auto-complete
    command->auto_complete = true;
  if (len > 0 && buf[len - 1] == '&') // background
    command->background = true;

  char *pch = strtok(buf, splitters);
  if (pch == NULL) {
    command->name = (char *)malloc(1);
    command->name[0] = 0;
  } else {
    command->name = (char *)malloc(strlen(pch) + 1);
    strcpy(command->name, pch);
  }

  command->args = (char **)malloc(sizeof(char *));

  int redirect_index;
  int arg_index = 0;
  char temp_buf[1024], *arg;
  while (1) {
    // tokenize input on splitters
    pch = strtok(NULL, splitters);
    if (!pch)
      break;
    arg = temp_buf;
    strcpy(arg, pch);
    len = strlen(arg);

    if (len == 0)
      continue; // empty arg, go for next
    while (len > 0 && strchr(splitters, arg[0]) != NULL) // trim left whitespace
    {
      arg++;
      len--;
    }
    while (len > 0 && strchr(splitters, arg[len - 1]) != NULL)
      arg[--len] = 0; // trim right whitespace
    if (len == 0)
      continue; // empty arg, go for next

    // piping to another command
    if (strcmp(arg, "|") == 0) {
      struct command_t *c = malloc(sizeof(struct command_t));
      int l = strlen(pch);
      pch[l] = splitters[0]; // restore strtok termination
      index = 1;
      while (pch[index] == ' ' || pch[index] == '\t')
        index++; // skip whitespaces

      parse_command(pch + index, c);
      pch[l] = 0; // put back strtok termination
      command->next = c;
      continue;
    }

    // background process
    if (strcmp(arg, "&") == 0)
      continue; // handled before

    // handle input redirection
    redirect_index = -1;
    if (arg[0] == '<')
      redirect_index = 0;
    if (arg[0] == '>') {
      if (len > 1 && arg[1] == '>') {
        redirect_index = 2;
        arg++;
        len--;
      } else
        redirect_index = 1;
    }
    if (redirect_index != -1) {
      command->redirects[redirect_index] = malloc(len);
      strcpy(command->redirects[redirect_index], arg + 1);
      continue;
    }

    // normal arguments
    if (len > 2 &&
        ((arg[0] == '"' && arg[len - 1] == '"') ||
         (arg[0] == '\'' && arg[len - 1] == '\''))) // quote wrapped arg
    {
      arg[--len] = 0;
      arg++;
    }
    command->args =
        (char **)realloc(command->args, sizeof(char *) * (arg_index + 1));
    command->args[arg_index] = (char *)malloc(len + 1);
    strcpy(command->args[arg_index++], arg);
  }
  command->arg_count = arg_index;

  // increase args size by 2
  command->args = (char **)realloc(command->args,
                                   sizeof(char *) * (command->arg_count += 2));

  // shift everything forward by 1
  for (int i = command->arg_count - 2; i > 0; --i)
    command->args[i] = command->args[i - 1];

  // set args[0] as a copy of name
  command->args[0] = strdup(command->name);
  // set args[arg_count-1] (last) to NULL
  command->args[command->arg_count - 1] = NULL;

  return 0;
}

void prompt_backspace() {
  putchar(8);   // go back 1
  putchar(' '); // write empty over
  putchar(8);   // go back 1 again
}
/**
 * Prompt a command from the user
 * @param  buf      [description]
 * @param  buf_size [description]
 * @return          [description]
 */
int prompt(struct command_t *command) {
  int index = 0;
  char c;
  char buf[4096];
  static char oldbuf[4096];

  // tcgetattr gets the parameters of the current terminal
  // STDIN_FILENO will tell tcgetattr that it should write the settings
  // of stdin to oldt
  static struct termios backup_termios, new_termios;
  tcgetattr(STDIN_FILENO, &backup_termios);
  new_termios = backup_termios;
  // ICANON normally takes care that one line at a time will be processed
  // that means it will return if it sees a "\n" or an EOF or an EOL
  new_termios.c_lflag &=
      ~(ICANON |
        ECHO); // Also disable automatic echo. We manually echo each char.
  // Those new settings will be set to STDIN
  // TCSANOW tells tcsetattr to change attributes immediately.
  tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

  show_prompt();
  buf[0] = 0;
  while (1) {
    c = getchar();
    // printf("Keycode: %u\n", c); // DEBUG: uncomment for debugging

    if (c == 9) // handle tab
    {
      buf[index++] = '?'; // autocomplete
      break;
    }

    if (c == 127) // handle backspace
    {
      if (index > 0) {
        prompt_backspace();
        index--;
      }
      continue;
    }

    if (c == 27 || c == 91 || c == 66 || c == 67 || c == 68) {
      continue;
    }

    if (c == 65) // up arrow
    {
      while (index > 0) {
        prompt_backspace();
        index--;
      }

      char tmpbuf[4096];
      printf("%s", oldbuf);
      strcpy(tmpbuf, buf);
      strcpy(buf, oldbuf);
      strcpy(oldbuf, tmpbuf);
      index += strlen(buf);
      continue;
    }

    putchar(c); // echo the character
    buf[index++] = c;
    if (index >= sizeof(buf) - 1)
      break;
    if (c == '\n') // enter key
      break;
    if (c == 4) // Ctrl+D
      return EXIT;
  }
  if (index > 0 && buf[index - 1] == '\n') // trim newline from the end
    index--;
  buf[index++] = '\0'; // null terminate string

  strcpy(oldbuf, buf);

  parse_command(buf, command);

  // print_command(command); // DEBUG: uncomment for debugging

  // restore the old settings
  tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
  return SUCCESS;
}
int process_command(struct command_t *command);
int redirect(struct command_t *command);
int createpipe(struct command_t *command,int amount1);
int amountpipes(struct command_t *command);
int amountredirections(struct command_t *command);
int execCommand(struct command_t *command);
int getDictionaryItem(struct dictionary_t *dict,char* key);
void deleteDictionaryItem(struct dictionary_t *dict,char* key);
void addDictionaryItem(struct dictionary_t **dict,char* key,int value);
void uniq(char** words,char* param);

int main() {
  while (1) {
    struct command_t *command = malloc(sizeof(struct command_t));
    memset(command, 0, sizeof(struct command_t)); // set all bytes to 0

    int code;
    code = prompt(command);
    if (code == EXIT)
      break;

    code = process_command(command);
    if (code == EXIT)
      break;

    free_command(command);
  }

  printf("\n");
  return 0;
}

int process_command(struct command_t *command) {
  int r;
  if (strcmp(command->name, "") == 0)
    return SUCCESS;

  if (strcmp(command->name, "exit") == 0)
    return EXIT;

  if (strcmp(command->name, "cd") == 0) {
    if (command->arg_count > 0) {
      r = chdir(command->args[0]);
      if (r == -1)
        printf("-%s: %s: %s\n", sysname, command->name, strerror(errno));
      return SUCCESS;
    }
  }
  pid_t pid = fork();
  if (pid == 0) // child
  {
    /// This shows how to do exec with environ (but is not available on MacOs)
    // extern char** environ; // environment variables
    // execvpe(command->name, command->args, environ); // exec+args+path+environ

    /// This shows how to do exec with auto-path resolve
    // add a NULL argument to the end of args, and the name to the beginning
    // as required by exec

    // TODO: do your own exec with path resolving using execv()
    // do so by replacing the execvp call below
      
    //REDIRECT

    print_command(command);
    int amount= amountpipes(command);


    if(amount > 0){
      createpipe(command,amount);
    }
    else{
        execCommand(command);
    }
      
      
      // EXECUTE COMMAND
      

    exit(0);
      
  }
  else {
    // TODO: implement background processes here
    wait(0); // wait for child process to finish
    return SUCCESS;
  }

  // TODO: your implementation here

  printf("-%s: %s: command not found\n", sysname, command->name);
  return UNKNOWN;
}

int redirect(struct command_t *command)
{
    char* input_file, output_file;
    int input_redirection=0,output_redirection=0;
    
    if(strcmp(command->redirects[1],"N/A")!=0 && strcmp(command->redirects[0],"N/A")!=0){
        input_redirection=1;
        output_redirection=1;
    }
    else if(strcmp(command->redirects[0],"N/A")!=0){
        input_redirection=1;
    }
    else if(strcmp(command->redirects[1],"N/A")!=0){
        output_redirection=1;
    }
    

    if(output_redirection==1){
        int out= creat(command->redirects[1],0644);
        if(out<0){
            fprintf(stderr, "Failed writing on %d\n", out);
            return(EXIT_FAILURE);
        }
        if(dup2(out, 1) < 0){
            printf("Unable to write the file.");
            exit(EXIT_FAILURE);
        }
        close(out);
        output_redirection=0;
    }
    
    if(input_redirection==1){
        int in= creat(command->redirects[1],0644);
        if(in<0){
            fprintf(stderr, "Failed reading on %d\n", in);
            return(EXIT_FAILURE);
        }
        if(dup2(in, 0) < 0){
            printf("Unable to read the file.");
            exit(EXIT_FAILURE);
        }
        close(in);
        input_redirection=0;
    }
    return 1;
}


int createpipe(struct command_t *command,int amount1)
{
    int i = 0;
    int index = 0;
    int amount = amount1;
    int pipecount= amount*2;
    int wr[amount*2];

    struct command_t *c= command;
    pid_t pid;
            
    //CREATING ALL PIPES
    for(i = 0; i < (amount); i++){
        if(pipe(wr + i*2) < 0) {
            perror("Error occured during piping");
            exit(1);
        }
    }
    // CHECKING ALL PIPES DURING LOOP
    while(c != NULL) {
        pid = fork();
        if(pid == 0) {
            if(c->next){
                int fdr1 = dup2(wr[index + 1], 1);
                
                if(fdr1 < 0){
                    perror("Error occured during piping");
                    exit(1);
                }
            }
            if(index != 0 ){
                int fdr2 = dup2(wr[index-2], 0);
                if(fdr2 < 0){
                    perror("Error occured during piping!");
                    exit(1);
                }
            }
            for(i = 0; i < (amount*2); i++){
                    close(wr[i]);
            }
            if(strcmp(c->name,"uniq") == 0){
                uniq(c->args,"");
            }
            else{
                int process =execvp(c->name,c->args);
                if(process < 0 ){
                        perror("Error occured during piping");
                        exit(1);
                }
            }
      
        }
        else if(pid < 0){
            perror("Error occured during piping");
            exit(1);
        }
        index += 2;
        c = c->next;
    }
    // CLOSING THE CHILD PIPES
    for(int a = 0; a < pipecount; a++){
        close(wr[a]);
    }
    // WAIT FOR THE CHILD PROCESSES FINISH
    for(int a = 0; a < (amount + 1); a++){
            wait(0);
    }
    return 0;
}


int amountpipes(struct command_t *command)
{
    struct command_t *c=command->next;
    int i=0;
    while(c!=NULL){
        c=c->next;
        i++;
    }
    return i;
    
}

int amountredirections(struct command_t *command)
{
    int count,a=0;
    
    while(a<3){
        if(strcmp(command->redirects[a],"N/A") != 0){
            count++;
        }
        a++;
    }
    return count;
}

int execCommand(struct command_t *command)
{
    // Forking a child
    pid_t pid = fork();
  
    if (pid == -1) {
        return -1;
    } else if (pid == 0) {
        char path[MAX_STRING_LENGTH];
        strcpy(path,"/bin/");
        strcat(path,command->name);
        
        if (execv(path, command->args) < 0) {
            perror("Command not found!");
        }
        exit(0);
    } else {
        wait(NULL);
        return 1;
    }
}
  

void uniq(char** words,char* param){
    struct dictionary_t **dict = malloc(sizeof(struct dictionary_t));
    size_t size= sizeof(words)/sizeof(words[0]);
    
    for(int i=0;i<size;i++){
        int amount = getDictionaryItem(*dict,words[i]);
        
        if(amount==0){
            addDictionaryItem(dict,words[i],1);
        }
        else{
            deleteDictionaryItem(*dict,words[i]);
            addDictionaryItem(dict,words[i],amount+1);
        }
    }
    
    struct dictionary_t *temp_dict= *dict;
    while(temp_dict != NULL){
        
        if(strcmp(param,"-c")==0 || strcmp(param,"--count")==0){
            printf("%d  %s\n",temp_dict->value,temp_dict->key);
        }
        else{
            printf("%s\n",temp_dict->key);
        }
        temp_dict= temp_dict->next;
    }
    
    free(dict);
}



int getDictionaryItem(struct dictionary_t *dict,char* key){
    struct dictionary_t *temp_dict = dict;
    
    while(temp_dict != NULL){
        if(strcmp(temp_dict->key,key)==0){
            return temp_dict->value;
        }
    }
    return 0;
}

void deleteDictionaryItem(struct dictionary_t *dict,char* key){
    struct dictionary_t *current= dict;
    struct dictionary_t *previous= NULL;
    
    while(current != NULL){
        if(strcmp(current->key,key) == 0){
            if(current->next != NULL){
                if(previous != NULL){
                    previous->next = current->next;
                }
                else{
                    dict= current->next;
                }
            }
            else if(previous != NULL){
                previous->next = NULL;
            }
            else{
                dict= NULL;
            }
            free(current);
            return;
        }
    }
    
}

void addDictionaryItem(struct dictionary_t **dict,char* key,int value){
    struct dictionary_t *temp = malloc(sizeof(struct dictionary_t));
    temp->value= value;
    temp->key= malloc(1+strlen(key));
    strcpy(temp->key,key);
    temp->next=*dict;
    *dict=temp;
}