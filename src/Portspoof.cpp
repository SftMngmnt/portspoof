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


#include "Server.h"
#include "Configuration.h"
#include "Threads.h"

#include "Revregex.h"
#include "connection.h"

Configuration* configuration;

int main(int argc, char **argv)
{

	Server* server;
	
	configuration = new Configuration();

	// bad arguments
	if( configuration->processArgs(argc,argv) )
	{
		fprintf(stdout,"\n Bad Arguments! " );
		exit(1);
	}

	// setup firewall
	if( configuration->getConfigValue(OPT_FIREWALL_INTF))
	{
		/**
		 * the network interface is specified for automatic firewall rules
		 * Rams Feature
		 * OS Check
		 * 	For each OS check to send in the correct IPtable rules
		 * 		windows and mac not configured yet
		 * 		Added to check for Iptable rules already entered
		 **/
		Utils::preConfigFirewall(configuration);

	}

	// check if both blocking options are set
	if( configuration->getConfigValue(OPT_TIMER_BLK) && configuration->getConfigValue(OPT_AUTO_BLK) )
	{
		fprintf(stdout,"\n Can only set one automatic IP blocking option! " );
		exit(1);
	}

	// run as daemon
	if( configuration->getConfigValue(OPT_RUN_AS_D) )
		Utils::daemonize(configuration);

	server = new Server(configuration);
	server->run();

	return 0;
}
