//===========================================================================//
// ratd.c - source file of main program
//===========================================================================//

//===========================================================================//
// ratd - Daemon for route reconstruction process
// by Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Copyright (C) 2005 Marcelo Duffles Donato Moreira
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//===========================================================================//

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <time.h>
#include <getopt.h>
#include "functions.h"


/* Global variables */
pcap_t		     *pkt_descr;		/* packet capture descriptor	*/
int      	     node_type;			/* initial or intermediate node	*/
unsigned	     nb_routes;			/* total number of routes       */
unsigned	     src_addr;			/* source address		*/
unsigned	     nb_neighbors;		/* number of neighbors		*/
char		     *neighbors_array[300];	/* array of neighbors		*/

int main (int argc, char **argv)
{
  unsigned	     i;				/* dummy variable		*/
  short int	     have_neighbor;		/* used like boolean		*/
  int		     ret;			/* returned value of functions	*/
  char		     is_src_host;		/* used like boolean		*/
  char		     *net_dev;			/* pointer to network device	*/
  char		     errbuf[PCAP_ERRBUF_SIZE];	/* libpcap error buffer		*/
  struct pcap_pkthdr pkt_hdr;			/* generic packet header	*/
  unsigned char	     *packet_data;		/* packet data			*/
  struct bpf_program filter_pgm;		/* filter program		*/
  bpf_u_int32	     dev_mask;			/* device`s subnet mask		*/
  bpf_u_int32	     dev_net;			/* device`s net address		*/
  pid_t		     child_pid;			/* child process ID		*/
  pid_t		     child_sid;			/* child process session ID	*/
  FILE		     *log_file;			/* /ratd/ratd.log		*/
  FILE		     *neighbor_file;		/* /ratd/neighborhood.dat	*/
  char		     temp_addr[16];		/* temporary address		*/
  char		     local_host_name[40];	/* local host name		*/
  struct hostent     *local_host;		/* local host			*/
  char		     string_options[] = "it";	/* string of options		*/

  
  
  /* structure of long options */
  static struct option options[] = 
  {
    {"initial_node",	  0, 0, INITIAL_NODE},
    {"intermediate_node", 0, 0, INTERMEDIATE_NODE},
    {0, 0, 0, 0}
  };
  
  //====================================================================//
  // Getting program options
  //====================================================================//
  
  if (argc != NB_ARGS) 
  {
    printf ("Usage: ./ratd [-i|--initial_node] [-t|--intermediate_node]\n");
    exit (EXIT_FAILURE);
  }
  
  opterr = 0;
  
  if (((node_type = getopt_long (argc, argv, string_options, options, NULL)) == EOF)
      || (node_type == '?'))
  {
    printf ("Usage: ./ratd [-i|--initial_node] [-t|--intermediate_node]\n");
    exit (EXIT_FAILURE);
  }
  
  if (getopt_long (argc, argv, string_options, options, NULL) != EOF)
  {
    printf ("More than one option have been selected.\n");
    printf ("Usage: ./ratd [-i|--initial_node] [-t|--intermediate_node]\n");
    exit (EXIT_FAILURE);
  }
    
  
  //====================================================================//
  // Initializing Daemon
  //====================================================================//
  
  /* Creating child process */
  child_pid = fork();
  if (child_pid == ERROR)
    exit (EXIT_FAILURE);

  /* Leaving the parent process */
  if (child_pid > 0)
    exit (EXIT_SUCCESS);

  /* Setting file creation mode mask */
  umask (0);
  
  /* Creating ratd daemon directory */
  if ((mkdir ("/ratd", 0) == ERROR) && (errno != EEXIST))
    exit (EXIT_FAILURE);
    
  /* Creating log file */
  log_file = fopen ("/ratd/ratd.log", "w");
  if (log_file == NULL)
    exit (EXIT_FAILURE);
  fclose (log_file);
  
  /* Writing initial message in log file */
  log_msg ("RATD Daemon Log File\n=====================\n\n");
  
  /* Creating a new session for the child process */
  child_sid = setsid ();
  if (child_sid == ERROR)
    exit (log_msg (error_messages[E_CREATING_CHILD_SESSION]));

  /* Changing the current working directory */
  if (chdir("/ratd"))
    exit (log_msg (error_messages[E_CHANGING_DIRECTORY]));

  /* Closing out the standard file descriptors */
  if (close(STDIN_FILENO))
    exit (log_msg (error_messages[E_CLOSING_STANDARD_FILES]));
  if (close(STDOUT_FILENO))
    exit (log_msg (error_messages[E_CLOSING_STANDARD_FILES]));
  if (close(STDERR_FILENO))
    exit (log_msg (error_messages[E_CLOSING_STANDARD_FILES]));

  /* Looking up a suitable network device */
  net_dev = pcap_lookupdev (errbuf);
  if (net_dev == NULL)
    exit (log_msg (errbuf));

  /* Getting IP address and subnet mask of the device */
  if (pcap_lookupnet ("any", &dev_net, &dev_mask, errbuf) == ERROR)
    exit (log_msg (errbuf));
    
  /* Opening network device for reading */
  pkt_descr = pcap_open_live ("any", BUFSIZ, NO_PROMISCUOUS_MODE, -1, errbuf);
  if (pkt_descr == NULL)
    exit (log_msg (errbuf));
    
  /* Now we will enter in daemon routine forever */

//====================================================================//
//========================== Daemon routine ==========================//
//====================================================================//    
routine:

  /* Compiling the filter program */
  if (node_type == INITIAL_NODE)
    if (pcap_compile (pkt_descr, &filter_pgm, ECHO_FILTER, 0, dev_mask) == ERROR)
      exit (log_msg (pcap_geterr (pkt_descr)));
  if (node_type == INTERMEDIATE_NODE)
    if (pcap_compile (pkt_descr, &filter_pgm, REQUEST_ROUTE_FILTER, 0, dev_mask) == ERROR)
      exit (log_msg (pcap_geterr (pkt_descr)));

  /* Setting the compiled filter program as the filter */
  if (pcap_setfilter (pkt_descr, &filter_pgm) == ERROR)
    exit (log_msg (pcap_geterr (pkt_descr)));

  /* Reading the next packet in network device */
  packet_data = (unsigned char *) pcap_next (pkt_descr, &pkt_hdr);
  if (packet_data == NULL)
    exit (log_msg (error_messages[E_NO_PACKET]));

  /* Saving the source address in network byte order */
  if (node_type == INTERMEDIATE_NODE)
    memcpy (&src_addr, &packet_data[28], 4);
  if (node_type == INITIAL_NODE)
  {
    if (gethostname (&local_host_name[0], 40) == ERROR)
      exit (log_msg (error_messages[E_GETHOSTNAME]));
    local_host = gethostbyname (local_host_name);
    if (local_host == NULL)
      exit (log_msg (error_messages[E_GETHOSTBYNAME]));
    memcpy (&src_addr, local_host->h_addr, 4);
  }

  
  //====================================================================//
  // Getting neighbors
  //====================================================================//
  
  /* Opening neighborhood file */
  neighbor_file = fopen ("/ratd/neighborhood.dat", "r");
  if (neighbor_file == NULL)
  {
    if (errno == ENOENT)
      exit (log_msg (error_messages[E_NO_NEIGHBOR_FILE]));
    exit (log_msg (error_messages[E_OPEN_NEIGHBOR_FILE]));
  }

  /* Filling neighbors_array */
  for (i = 0; (ret = get_neighbor_addr (neighbor_file, &temp_addr[0])) != RATD_EOF; i++)
  {
    if (ret != OK)
    {
      fclose (neighbor_file);
      exit (log_msg (error_messages[ret])); 
    }       
    neighbors_array[i] = (char *) calloc (strlen (temp_addr) + 1, sizeof (char));
    strcpy (neighbors_array[i], temp_addr);
  }
  nb_neighbors = i;
  fclose (neighbor_file);  


  //====================================================================//
  // Sending a packet with the bloom filter to neighbors which belong
  // to the route (according to the filter)
  //====================================================================//
  
  /* Note that the first argument (destination address) in is_in_filter()
   * must be in host byte order						*/
  for (i = 0, have_neighbor = 0; i < nb_neighbors; i++)
  {
    ret = verify_host_addr (src_addr, neighbors_array[i], &is_src_host);
    if (ret != OK)
      exit (log_msg (error_messages[ret]));

    if ((!is_src_host) &&
	(is_in_filter (ntohl (inet_addr (neighbors_array[i])), &packet_data[38])))
    {
      have_neighbor = 1;
      if (send_packet (neighbors_array[i], packet_data, REQUEST_ROUTE) == ERROR)
        exit (EXIT_FAILURE);
    }
  }
        
  /* If there aren't neighbors, then we have to send a ROUTE_REPLY packet *
   * to initial node and go back to the begining of the routine	  	  */
  if (!have_neighbor)
  {
    memcpy (&temp_addr[0], &packet_data[85], 4);
    if (send_packet (inet_ntoa (*((struct in_addr *) &temp_addr[0])), packet_data, ROUTE_REPLY) == ERROR)
      log_msg (error_messages[E_SEND_ROUTE_REPLY_PACKET]);

    /* Freeing alocated memory */
    for (i = 0; i < nb_neighbors; i++)
      free (neighbors_array[i]);

    goto routine;
  }
      
    
  //====================================================================//
  // Waiting for answers.
  // The route must be in the received packet data.
  //====================================================================//
  
  /* Compiling the filter program */
  if (node_type == INITIAL_NODE)
    if (pcap_compile (pkt_descr, &filter_pgm, ROUTE_REPLY_FILTER, 0, dev_mask) == ERROR)
      exit (log_msg (pcap_geterr (pkt_descr)));
  if (node_type == INTERMEDIATE_NODE)
    if (pcap_compile (pkt_descr, &filter_pgm, REQUEST_ROUTE_FILTER, 0, dev_mask) == ERROR)
      exit (log_msg (pcap_geterr (pkt_descr)));

  /* Setting the compiled filter program as the filter */
  if (pcap_setfilter (pkt_descr, &filter_pgm) == ERROR)
    exit (log_msg (pcap_geterr (pkt_descr)));
    
  /* Looping... */
  nb_routes = 1;
  if (pcap_loop (pkt_descr, -1, process_packet, NULL) == ERROR)
    exit (log_msg (pcap_geterr (pkt_descr)));

  /* Freeing alocated memory */
  for (i = 0; i < nb_neighbors; i++)
    free (neighbors_array[i]);
    
  /* Going back to the begining of the routine... */
  goto routine;
//====================================================================//
//====================== End of daemon routine =======================//
//====================================================================//  
  
  exit (EXIT_SUCCESS);
}
