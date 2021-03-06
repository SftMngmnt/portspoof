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

#include <string>

#include "Server.h"
#include "Utils.h"
#include "connection.h"

using std::string;

pthread_cond_t new_connection_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t new_connection_mutex = PTHREAD_MUTEX_INITIALIZER;

Thread threads[MAX_THREADS];

/**
* This formats the legible, not binary, ip .
* fd = newsockfd
* ipstr = points to the returned ip addr
*/
int get_ipstr_server(int fd, char *ipstr)
{
  socklen_t len;
  struct sockaddr_storage addr;

  len = sizeof(struct sockaddr_storage);
  // int get_ipstr(int fd, char *ipstr) { ... }
  getpeername(fd, (struct sockaddr *)&addr, &len);

  if (addr.ss_family == AF_INET)
  {
    struct sockaddr_in *s = (struct sockaddr_in *)&addr;
    inet_ntop(AF_INET, &s->sin_addr, ipstr, INET_ADDRSTRLEN);
  }
  else
  { // AF_INET6
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
    inet_ntop(AF_INET6, &s->sin6_addr, ipstr, INET6_ADDRSTRLEN);
  }
  return 1;
}


Server::Server(Configuration* configuration)
{	
	this->configuration = configuration;

	// !!! All threds created Here //
	/*  create thread pool */
	for(int i = 0; i < this->configuration->getThreadNr(); i++)
	{
		pthread_create(&threads[i].tid, NULL, &process_connection, (void *) i);
		threads[i].client_count = 0;
	}
		
	/* create a socket */
	sockd = socket(PF_INET, SOCK_STREAM, 0);
	if (sockd == -1)
	{
		perror("Socket creation error");
		exit(1);
	}

	int n = 1;
	setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR , &n, sizeof(n));

	/* server address  - by default localhost */
	my_name.sin_family = PF_INET;
	if(configuration->getConfigValue(OPT_IP))
	{
		fprintf(stdout,"-> Binding to iface: %s\n",configuration->getBindIP().c_str());
		inet_aton(configuration->getBindIP().c_str(), &my_name.sin_addr);

	}
	else
	my_name.sin_addr.s_addr = INADDR_ANY;

	if(configuration->getConfigValue(OPT_PORT))
	{
		fprintf(stdout,"-> Binding to port: %d\n",configuration->getPort());
		my_name.sin_port = htons(configuration->getPort());

	}
	else
	{
		my_name.sin_port = htons(DEFAULT_PORT);
	}

	status = bind(sockd, (struct sockaddr*)&my_name, sizeof(my_name));

	if (status == -1)
	{
		perror("Binding error");
		exit(1);
	}

	// Set queue sizeof
	status = listen(sockd, 10);
	if (status == -1)
	{
		perror("Listen set error");
		exit(1);
	}

	return;
}

/**
 * Server waits for new connections, spawns threads --> process_connection
 */
bool Server::run()
{

	int choosen;
	int same_newsockfd;
	string temp = "0.0.0.0", compare_me;
    char ipstr[INET6_ADDRSTRLEN];
	memset(ipstr, '\0', INET6_ADDRSTRLEN);
    char cmp_ipstr[INET6_ADDRSTRLEN];
	memset(cmp_ipstr, '\0', INET6_ADDRSTRLEN);

	while(1)
	{

		/* wait for a connection */
		addrlen = sizeof(peer_name);
		newsockfd = accept(sockd, (struct sockaddr*)&peer_name,(socklen_t*) &addrlen);

		if (newsockfd < 0)
		{
			perror("ERROR on accept");
		}
		else
		{
			nonblock(newsockfd);

			/**
			 * BLOCKING IP MECHANISM
			 * Don't try to check the IP add to firewall rules if either option is not set
			 * configuration->getConfigValue(OPT_AUTO_BLK)
			 * configuration->getConfigValue(OPT_TIMER_BLK)
			 */
			if( configuration->getConfigValue(OPT_TIMER_BLK) || configuration->getConfigValue(OPT_AUTO_BLK) )
			{
				/**
				 * trying to single out ONE ip per connection in thread pool.
				 * Putting inside mutex just incase.
				 */
				get_ipstr_server(newsockfd, cmp_ipstr);
				compare_me = string(cmp_ipstr);
				if( temp.compare(compare_me) != 0 )
				{

					get_ipstr_server(newsockfd, ipstr);
					temp = string(ipstr);
					fprintf(stdout,"\nnew connection: %s",ipstr );

					/**
					 * immediate blacklisting can be done here
					 * all rules for blocking are handled in Utils for different OS's
					 *
					 */
					if( configuration->getConfigValue(OPT_TIMER_BLK) )
					{
						fprintf(stdout,"\nBlocking %s -After- Scan is complete ", ipstr);
						Utils::blockIP(temp, configuration->getBlacklistName() );
					}

					if( configuration->getConfigValue(OPT_AUTO_BLK) )
					{
						fprintf(stdout,"\nBlocking %s -Before- Scan is complete ", ipstr);
						Utils::blockIP(temp, configuration->getBlacklistName() );
					}

				}
			}

			start:

			pthread_mutex_lock(&new_connection_mutex);

			choosen=choose_thread();

			if( choosen == -1)
			{
				pthread_mutex_unlock(&new_connection_mutex);
				sleep(1);
				goto start;
			}


			if(configuration->getConfigValue(OPT_DEBUG))
			{
				fprintf(stdout," new conn - thread choosen: %d -  nr. of connections already in queue: %d\n",choosen,threads[choosen].client_count);
				fflush(stdout);
			}


			for(int i = 0; i < MAX_CLIENT_PER_THREAD; i++)
			{
				if(threads[choosen].clients[i] == 0)
				{
					threads[choosen].clients[i] = newsockfd;
					threads[choosen].client_count++;
					break;
				}
			}

			pthread_mutex_unlock(&new_connection_mutex);
		}
	}

return 0;

}

int Server::choose_thread()
{
	int i=this->configuration->getThreadNr()-1;
	int min = i;
	while(i >=0)
	{
		if(threads[i].client_count < threads[min].client_count)
		{
			min = i;
		}
		i--;
	}		

	if(threads[min].client_count==MAX_CLIENT_PER_THREAD)
		return -1;
	
	return min;
}



