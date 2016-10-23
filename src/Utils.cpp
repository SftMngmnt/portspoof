/*
 *   Portspoof  - Service Signature Emulator  / Exploitation Framework Frontend   
 *   Copyright (C) 2012 Piotr Duszyński <piotr[at]duszynski.eu>
 *
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by the
 *   Free Software Foundation; either version 2 of the License, or (at your
 *   option) any later version.
 * 
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *   See the GNU General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, see <http://www.gnu.org/licenses>.
 * 
 *   Linking portspoof statically or dynamically with other modules is making
 *   a combined work based on Portspoof. Thus, the terms and conditions of
 *   the GNU General Public License cover the whole combination.
 * 
 *   In addition, as a special exception, the copyright holder of Portspoof
 *   gives you permission to combine Portspoof with free software programs or
 *   libraries that are released under the GNU LGPL. You may copy
 *   and distribute such a system following the terms of the GNU GPL for
 *   Portspoof and the licenses of the other code concerned.
 * 
 *   Note that people who make modified versions of Portspoof are not obligated
 *   to grant this special exception for their modified versions; it is their
 *   choice whether to do so. The GNU General Public License gives permission
 *   to release a modified version without this exception; this exception
 *   also makes it possible to release a modified version which carries
 *   forward this exception.
 */

 
#include <sys/types.h>
#include <unistd.h>

#include "Utils.h"
using std::string;


pthread_cond_t log_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Run system commands such as making iptables i.e NAT rules,
 * building ipset list, iptables DROP for ipset.
 * @param option; if both options are sent in as parameters: port & network card
 */
void Utils::SystemCommands(Configuration* configuration)
{
	std::string interface = configuration->getInterface();
	int port = configuration->getPort();
	char *commands[CMNDS];
	char *single_command = (char*) malloc( MAX_INPUT * sizeof(char) );
	/**
	 * START PORTSPOOF PROCESS
	 * 1: Open firewall port
	 * 	- if already open, leave alone
	 * 	- else: reload firewall after new rule entered
	 * 2: Iptables NAT
	 *  - if already set check port number
	 *  - else write rule
	 * 3: ipset list create
	 *  - if list exists leave alone
	 *  - else: write
	 */
	/**
   # Open the port to direct all traffic through NAT on port 4444

	echo "creating portspoof firewall rules..."
	echo "opening port"
	echo "ufw allow proto tcp from any to any port $PORT"
	ufw allow proto tcp from any to any port $PORT
	ufw reload
	echo "setting iptables rerouting into nat from $PORT"
	echo "iptables -t nat -A PREROUTING -i $IFACE -p tcp -m tcp --dport 1:65535 -j REDIRECT --to-ports $PORT"
	iptables -t nat -A PREROUTING -i $IFACE -p tcp -m tcp --dport 1:65535 -j REDIRECT --to-ports $PORT

	# select certain ports
	# everything minus 22 & 80
	# iptables -t nat -A PREROUTING -i eth0 -p tcp -m tcp -m multiport --dports 1:21,23:79,81:65535 -j REDIRECT

	# ipset
	# drop all packets
	echo "creating iptables rules for ipset..."

	# create ipset with hash_size: 16384 maxelem: 500000
	echo "making ipset list ..."
	echo "ipset create $NAME -exist hash:net family inet hashsize 16384 maxelem 500000"
	ipset create $NAME -exist hash:net family inet hashsize 16384 maxelem 500000


	echo "iptables -I INPUT -m set --match-set $NAME src -j DROP"
	iptables -I INPUT -m set --match-set $NAME src -j DROP

	# blacklist the ip
	# ipset add port_blacklist 111.222.333.444

	# remove ip
	# ipset port_blacklist 111.222.333.444
	 */

	//commands = { "iptables", "-h" };

	single_command = "iptables -h";
	commands = parseCommand(single_command);

	forking(commands);
	/* pRoCeSs cOmMaNdS eNd */

	/* Clean up all the memory space */
	//TODO

}

/**
 * Parse a whole string into an array
 */
char* Utils::parseCommand(char *input)
{
	int i=0;
	char *commands[CMNDS], *buffer;

	/* make temporary space to tokenize commands with for copying out of input */
	buffer = (char*) malloc( strlen(input) * sizeof(char) );

	for(i = 0; i < CMNDS; i++)
	{	/* restricting space that user can input, keep BO's out perhaps */
		commands[i] = (char*)malloc(CMND_LEN * sizeof(char));
		memset(commands[i],0, CMND_LEN);	/* set all memory to /0 */
	}

	i=0;
	while( (buffer = strsep(&input, DELIM) ) != NULL)
	{	/**
		 * with strncmp... trying to prevent exit when over MAX_CMND "spaces"
		 * entered but doesn't help.
		 **/
		if( (strlen(buffer) >= 1) && (strcmp(buffer," ")!=0) )
		{	/* everything that is worthwhile to copy is in here or else is null */
			commands[i] = strndup(buffer,CMND_LEN);	/* Restrict length of commands */
			/* always add a NULL byte */
			commands[i+1]='\0';
			countD++;

			if( strlen( commands[i] ) == 0)
			{
				commands[i]= NULL;
			}
			/* placing iterator here, ignores lots of potential problems with input */
			i++;
		}
		else
		{	/* without this no NULLs are in commands array and execvp will return error */
			commands[i] = NULL;
		}

		if(i > MAX_CMND)
		{	/**
			 * More than MAX_CMND of delimiters have been entered and will
			 * overwrite the stack; overwriting pflag from main() which will
			 * exit the loop and kill the program.  For protection we need to
			 * prevent that in a number of different ways. This way works a bit.
			 **/
			printf("More than %d, commands/arguments entered, ignored extra.\n",MAX_CMND);
			input=NULL;
		}
	}
	return commands;
}

/**
 * handle forking out the individual system commands entirely on their own
 */
void Utils::forking(char* commands[CMNDS])
{
	/* fork to run system command */
	pid_t pid = fork();
	int status, exec_ret;

	/* take over child with execvp */
	if(pid == 0)  /* CHILD */
	{	/* execvp uses environment PATH set by shell; /bin/,/usr/bin, etc. */
		fprintf(stdout,"%s\n", commands[0]);
		fprintf(stdout,"NOT EXECUTING YET %s %s %s %s\n",commands[0],commands[1],commands[2],commands[3]);
		//exec_ret = execvp(commands[0],commands);

		/* watching when an error happens, PATH can't find command, kill child*/
		if(exec_ret == -1)
		{
			fprintf(stdout,"\n%s: Error with command.\n",commands[0]);
			exit(0); /* Kill the child */
		}
	}

	wait( &status ); /* wait on child/everyone before proceeding */
	if (pid !=0)	/* PARENT */
	{
		fflush( NULL );
	}

	if(exec_ret == -1)
	{
		fprintf(stdout,"\n%s: Setup failed.\n",commands[0]);
		fprintf(stdout,"-> check input and rerun\n");
		exit(1);
	}
}


void Utils::hexdump(void *mem, unsigned int len)
{
    unsigned int i, j;
    
    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if(i % HEXDUMP_COLS == 0)
        {
            fprintf(stdout,"0x%06x: ", i);
        }
        
        /* print hex data */
        if(i < len)
        {
            fprintf(stdout,"%02x ", 0xFF & ((char*)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            fprintf(stdout,"   ");
        }
        
        /* print ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if(j >= len) /* end of block, not really printing */
                {
                    putchar(' ');
                }
                else if(isprint(((char*)mem)[j])) /* printable char */
                {
                    putchar(0xFF & ((char*)mem)[j]);
                }
                else /* other char */
                {
                    putchar('.');
                }
            }
            putchar('\n');
        }
    }
}

std::vector<char> Utils::wrapNMAP(string wrapper,std::vector<char> payload)
{
	stringstream ss;	
	string str;
	std::vector<char> result_vector;
	
	ss<<wrapper.substr(0,wrapper.find(FUZZING_KEYWORD));
	str=ss.str();
	
	for(unsigned int i=0; i<str.length();i++)
		result_vector.push_back(str[i]);	
	
	result_vector.insert(result_vector.end(),payload.begin(),payload.end());
	
	ss.str("");
	ss<<wrapper.substr(wrapper.find(FUZZING_KEYWORD)+strlen(FUZZING_KEYWORD),wrapper.size());
	
	str=ss.str();
	
	for(unsigned int i=0; i<str.length();i++)
		result_vector.push_back(str[i]);		
	
	return result_vector;
}

std::vector<char> Utils::str2vector( std::string& s)
{
	std::vector<char> result_vector;
	
	for(int i=0; i<s.length();i++)
		result_vector.push_back(s[i]);
		
	return result_vector;
	
}

int Utils::isNumeric (const char * s)
{
    if (s == NULL || *s == '\0' || isspace(*s))
     return 0;
    char * p;
    strtod(s, &p);
    return *p == '\0';
}


std::vector<char> Utils::unescape(std::vector<char> & s)
{
  std::vector<char> res;
  vector<char>::const_iterator it = s.begin();
  while (it != s.end())
  {
    char c = *it++;
    if (c == '\\' && it != s.end())
    {
      switch (*it++) {
      case 'n': c = '\n'; break;
      case 'r': c = '\r'; break;
      case 't': c = '\t'; break;

      // all other escapes
      default: 
        // invalid escape sequence - skip it. alternatively you can copy it as is, throw an exception...
        continue;
      }
    }
    res.push_back(c);
  }

  return res;
}


char * Utils::get_substring_value(char* str)
{
	int i=0;
	int soffset=-1,eoffset=-1;
	for(i;i<strlen(str);i++)
	{
		if(str[i]=='"')
		{
		
		if(soffset==-1)
			soffset=i;
		else if(eoffset==-1)
			{
				eoffset=i;
				break;
			}
		else
			{
			fprintf(stdout,"Error in configuration file1");
			exit(1);
			}
		}
	}
	
	if(soffset==-1 || eoffset==-1)
	{
			fprintf(stdout,"Error in configuration file2");
			exit(1);
	}
				
	char *substr=(char*)malloc(eoffset-soffset);
	memset(substr,0,eoffset-soffset);
	memcpy(substr,str+soffset+1,eoffset-soffset-1);
	return substr;	
}


void Utils::log_create(const char* file){
  
  FILE *fp = fopen(file, "a");
    if (fp == NULL) {
      fp = fopen(file, "w");
    }
  fclose(fp);
  return;
  
}

void Utils::log_write(Configuration* configuration,const char* msg) {

  pthread_mutex_lock(&log_mutex);

  if(configuration->getConfigValue(OPT_LOG_FILE))
  {
    FILE *fp = fopen(configuration->getLogFile().c_str(), "a");
    if (fp == NULL) {
        fprintf(stdout,"Error opening file: %s \n",configuration->getLogFile().c_str());
      exit(1);
    }
    
    fprintf(fp,"%s",msg);
    fclose(fp);
    
  } 
  
  if(!(configuration->getConfigValue(OPT_SYSLOG_DIS)))
  {
  openlog(SYSLOG_NAME, LOG_PID|LOG_CONS, LOG_USER);
  syslog(LOG_INFO," %s",msg);
  closelog();
  }
  pthread_mutex_unlock(&log_mutex);
  
  return;

}


void Utils::daemonize(Configuration* configuration)
{

  const string &dir = "/";
    const std::string &stdinfile = "/dev/null";
    const std::string &stdoutfile = "/dev/null";
    const std::string &stderrfile = "/dev/null";


  umask(0);


  rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) < 0) 
  {
    throw std::runtime_error(strerror(errno));
  }
 


  pid_t pid;
  if ((pid = fork()) < 0) 
  {
    throw std::runtime_error(strerror(errno));
  } else if (pid != 0) { //parent
    exit(0);
  }


  setsid();
 
  if (!dir.empty() && chdir(dir.c_str()) < 0) 
  {
    throw std::runtime_error(strerror(errno));
  }
 

   if (setgid(configuration->getGroupid()) != 0)
   {
  fprintf(stdout,"setgid: Unable to drop group privileges: %s", strerror(errno));
  fflush(stdout);
  exit(-1);
   }
   

   if (setuid(configuration->getUserid()) != 0)
    {
  fprintf(stdout,"setuid: Unable to drop user privileges: %s", strerror(errno));
  fflush(stdout);
  exit(-1);
   }




  if (rl.rlim_max == RLIM_INFINITY) 
  {
    rl.rlim_max = 1024;
  }
 
  for (unsigned int i = 0; i < rl.rlim_max; i++) 
  {
    close(i);
  }
 


  int fd0 = open(stdinfile.c_str(), O_RDONLY);
  int fd1 = open(stdoutfile.c_str(),
      O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
  int fd2 = open(stderrfile.c_str(),
      O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
 
 
  if (fd0 != STDIN_FILENO || fd1 != STDOUT_FILENO || fd2 != STDERR_FILENO) 
  {
    throw runtime_error("new standard file descriptors were not opened as expected");
  }
  


}
