//===========================================================================//
// functions.c - source file of secundary functions
//===========================================================================//

//===========================================================================//
// ratd - Daemon for route reconstruction process
// by Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Copyright (C) 2005 Marcelo Duffles Donato Moreira
//
// Some functions have been based on the ping program
// by Gustavo L. Coutinho <gustavo@gta.ufrj.br>
//
// Some functions have been based on the gbf - Generalized Bloom
// Filter implementation by Rafael P. Laufer <rlaufer@gta.ufrj.br>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>       
#include <netinet/in.h>       
#include <netinet/ip.h>       
#include <netinet/ip_icmp.h>  
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include "functions.h"


/* Global variable which contains the error messages */
char *error_messages[] =
{
  /* 00 */ "Success.",
  /* 01 */ "Error while creating child process.",
  /* 02 */ "Error changing current directory.",
  /* 03 */ "Error closing standard files.",
  /* 04 */ "No packet has been read.",
  /* 05 */ "ICMP protocol is unknown.",
  /* 06 */ "Error opening socket.",
  /* 07 */ "Error in IP header.",
  /* 08 */ "Error sending datagram.",
  /* 09 */ "Invalid host.",
  /* 10 */ "Error opening neighborhood file.",
  /* 11 */ "Neighborhood file (/ratd/neighborhood.dat) doesn't exist.",
  /* 12 */ "Error: send_packet()",
  /* 13 */ "Error: build_packet()",
  /* 14 */ "Error: log_msg()",
  /* 15 */ "Error: gethostname()",
  /* 16 */ "Error: gethostbyname()",
  /* 17 */ "Error: get_neighbor_addr()",
  /* 18 */ "Error: Invalid neighbor address.",
  /* 19 */ "Error opening route file for write.",
  /* 20 */ "Error sending route reply packet.",
  /* 21 */ "Error sending request route packet.",
  /* 22 */ "Error verify_host_addr().",
};

int verify_host_addr (unsigned host, char *addr, char *bool)
{
  unsigned line=1, host_line=999999, addr_line=999998;
  int i;
  FILE *file;
  char temp[16+1];
  char c;

  *bool = 0;

  if ((addr == NULL) || (bool == NULL))
    return (E_VERIFY_HOST_ADDR);

  if (host == inet_addr (addr))
  { 
    *bool = 1;
    return (OK);
  }
  
  /* Opening neighborhood file */
  file = fopen ("/ratd/neighborhood.dat", "r");
  if (file == NULL)
  {
    if (errno == ENOENT)
      return (E_NO_NEIGHBOR_FILE);
    return (E_OPEN_NEIGHBOR_FILE);
  }

  for (i = 0; i < 16; i++)
  {
    if ((fread (&temp[i], 1, 1, file)) != 1)
    {
      if (ferror (file))		/* error while reading file */
      {
        fclose (file);	
        return (E_VERIFY_HOST_ADDR);
      }	

      fclose (file);
      return (OK);			/* end of file is reached */
    }

    c = temp[i];
    if (temp[i] == '\n')
    {
      temp[i] = '\0';
      if (!strcmp (&temp[0], addr))
        addr_line = line; 
      if (host == inet_addr (&temp[0]))
        host_line = line;
      line++;
      i = -1;
    }
    if (temp[i] == ' ')
    {
      temp[i] = '\0';
      if (!strcmp (&temp[0], addr))
        addr_line = line; 
      if (host == inet_addr (&temp[0]))
        host_line = line;
      i = -1;
    }
	
    if (host_line == addr_line)
    {
      *bool = 1;
      fclose (file);
      return (OK);
    }

    if ((host_line != 999999) && (addr_line != 999998) &&
        (host_line != addr_line) && (c != ' '))
    {
      fclose (file);
      return (OK);
    }
  }

  fclose (file);
  return (E_INVAL_ADDR);  
}

short int is_null (char *array)
{
  short int i;
  
  for (i = 0; i < 4; i++)
    if (array[i] != 0)
      return (0);
      
  return (1);
}

/* Function to log messages in log file */
unsigned log_msg (char *message)
{
  FILE *log_file;
    
  log_file = fopen ("/ratd/ratd.log", "a+");
  if (log_file == NULL)
    return (EXIT_FAILURE);
  
  if (message == NULL)
  {
    fprintf (log_file, "%s\n", error_messages[E_LOG_MSG]);
    fclose (log_file);
    return (EXIT_FAILURE);
  }

  fprintf (log_file, "%s\n", message);

  fclose (log_file);
  return (EXIT_FAILURE);
};

//=========================================================================//
// Checksum function
// Based on the ping program by Gustavo L. Coutinho <gustavo@gta.ufrj.br>
//=========================================================================//
unsigned short csum (unsigned short *buf, int nwords)
{
  unsigned long sum;

  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return ~sum;
};

//=========================================================================//
// Function to fill packet structure with the correct data
// Based on the ping program by Gustavo L. Coutinho <gustavo@gta.ufrj.br>
//=========================================================================//
int build_packet (struct sockaddr_in *sin, char *datagram, struct ip **iph,
		  struct icmphdr **icmph, struct hostent *dest_host,
		  unsigned char *packet_data, unsigned char flag)
{
  char *option = 0;		/* the option field	*/
  unsigned i,j;			/* dummy variable	*/
  unsigned u32_addr;		/* address in NBO	*/
  struct hostent *local_host;	/* local host		*/
  char local_host_name[40];	/* local host name	*/
  char local_host_addr[4];	/* local host address	*/

  if ((sin == NULL) || (datagram == NULL) || (iph == NULL) ||
      (icmph == NULL) || (dest_host == NULL) || (packet_data == NULL))
    return (E_BUILD_PACKET);
    
  /*-----------------------------------------------------------------*
   * Filling the sockaddr_in structure with family (AF_INET) and     *
   * destination address.                                            *
   *-----------------------------------------------------------------*/
  sin->sin_family = AF_INET;
  sin->sin_port   = 0;
  memcpy (&sin->sin_addr.s_addr, dest_host->h_addr, dest_host->h_length);

  /*------------------------------------------------------------*
   * We are building the whole packet in 'datagram' and the IP  *
   * header is at the beginning of the 'datagram' buffer        *
   *------------------------------------------------------------*/
  *iph = (struct ip *) datagram;

  /*---- Filling the packet with zeros -----*/
  memset (datagram, 0, PACKET_SIZE);

  /*----- Building the IP options -----*/
  option = datagram + sizeof (struct ip);	/* setting up the option pointer */
  option[0] = 25|0x80;				/* setting the option id         */
  option[1] = OPTION_GBF_SIZE;			/* the size of the option field  */
  for (i = 0; i < OPTION_GBF_SIZE - 2; i++)	/* filling the option with data  */
   option[i+2] = packet_data[i+38];

  /*---- Building the IP Header -----*/
  (*iph)->ip_v   = 4;				/* IP version                           */
  (*iph)->ip_hl  = 5 + OPTION_GBF_SIZE/4;	/* IP header size in 32-bits words      */
  (*iph)->ip_tos = 0;				/* Type of Service (ToS), not needed    */
  (*iph)->ip_len = PACKET_SIZE;			/* total size of the packet in bytes    */
  (*iph)->ip_id  = 0;				/* this value doesn't matter, kernel    */
	 					/* sets one automatically               */
  (*iph)->ip_off = 0;				/* fragment offset, not needed          */
  (*iph)->ip_ttl = 127;				/* Time To Live (TTL)                   */
  (*iph)->ip_p   = 1;				/* Protocol = ICMP = 1                  */
  (*iph)->ip_sum = 0;				/* set to 0 before calculating checksum */
  (*iph)->ip_src.s_addr = 0;			/* source address filled in by kernel   */
  (*iph)->ip_dst.s_addr = sin->sin_addr.s_addr;	/* destination address			*/

  /*----- Calculating IP checksum -----*/
  (*iph)->ip_sum = csum ((unsigned short *) (*iph), (*iph)->ip_len >> 1);

  /*----- Building the ICMP Header -----*/
  (*icmph) = (struct icmphdr *)	   /* setting up the ICMP pointer          */
  	     (datagram + sizeof(struct ip) + OPTION_GBF_SIZE);
  (*icmph)->type = 0;              /* ECHOREPLY requires type 0 and code 0 */
  (*icmph)->code = 0;
  (*icmph)->checksum = 0;          /* set to 0 before calculating checksum */
  (*icmph)->un.echo.id = 18;       /* any value will do                    */
  (*icmph)->un.echo.sequence = 33; /* any value will do                    */
 
  /*----- Getting local host address -----*/
  if (gethostname (&local_host_name[0], 40) == ERROR)
    return (E_GETHOSTNAME);
  local_host = gethostbyname (local_host_name);
  if (local_host == NULL)
    return (E_GETHOSTBYNAME);
  if (node_type == INITIAL_NODE)
    memcpy (&local_host_addr[0], local_host->h_addr_list[0], 4);
  if (node_type == INTERMEDIATE_NODE)
    for (j = 0; local_host->h_addr_list[j] != NULL; j++)
    {
      memcpy (&u32_addr, local_host->h_addr_list[j], 4);
      if (is_in_filter (ntohl (u32_addr), &packet_data[38]))
      {
        memcpy (&local_host_addr[0], local_host->h_addr_list[j], 4);
        break;
      }
    }

  /*----- Setting flag -----*/
  i = FLAG_INDEX;
  datagram[i] = flag;
  
  /*----- Inserting local host address (network byte order) in packet data -----*/
  i += 1;
  if (node_type == INITIAL_NODE)
    memcpy (&datagram[i], &local_host_addr[0], 4);
  if (node_type == INTERMEDIATE_NODE)
  {
    memcpy (&datagram[i], &packet_data[85], DATA_SIZE-1);
    while ((i < PACKET_SIZE) && (!is_null (&datagram[i])))
      i += 4;
    if (packet_data[84] == REQUEST_ROUTE)
      memcpy (&datagram[i], &local_host_addr[0], 4);
  }  
 
  /*----- Calculating ICMP checksum (8 = ICMP ECHO header size) -----*/
  (*icmph)->checksum = csum ((unsigned short *) (*icmph), (DATA_SIZE + sizeof (struct icmphdr)) >> 1);
  
  return (OK);
};

//=========================================================================//
// Function to send packet to dest_addr
// Based on the ping program by Gustavo L. Coutinho <gustavo@gta.ufrj.br>
//=========================================================================//
int send_packet (char *dest_addr, unsigned char *packet_data, unsigned char flag)
{
  int		     ret;			/* returned value of functions	*/
  int		     s;				/* socket file descriptor	*/
  struct sockaddr_in sin;			/* source socket structure	*/
  char		     datagram[PACKET_SIZE];	/* the whole packet (IP + ICMP)	*/
  struct ip	     *iph;			/* the IP header structure	*/
  struct icmphdr     *icmph;			/* the ICMP header structure	*/
  struct protoent    *proto;			/* the protocol structure	*/
  struct hostent     *dest_host;		/* destination host structure	*/
  
  if ((dest_addr == NULL) || (packet_data == NULL))
  {
    log_msg (error_messages[E_SEND_PACKET]);
    return (ERROR);
  }
    
  /* Getting the protocol number for ICMP */
  proto = getprotobyname ("icmp");
  if (proto == NULL)
  {
    log_msg (error_messages[E_UNKNOWN_PROTO_ICMP]);
    return (ERROR);
  }

  /* Opening a raw socket */
  s = socket (AF_INET, SOCK_RAW, proto->p_proto);
  if (s == ERROR)
  {
    log_msg (error_messages[E_OPENING_SOCKET]);
    return (ERROR);
  }
    
  /* Droping root priviledges */
  #ifdef __linux__
    setuid (getuid ());
  #endif

  /* Setting destination host*/
  dest_host = gethostbyname (dest_addr);
  if (dest_host == NULL)
  {
    log_msg (error_messages[E_GETHOSTBYNAME]);
    return (ERROR);
  }
    
  /* Building the new packet */
  ret = build_packet (&sin, &datagram[0], &iph, &icmph, dest_host, packet_data, flag);
  if (ret != OK)
  {
    log_msg (error_messages[ret]);
    return (ERROR);
  }

  /* Notifying the kernel that we have our own IP header */
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, datagram, sizeof (struct ip)) == ERROR)
  {
    log_msg (error_messages[E_IP_HEADER]);
    return (ERROR);
  }

  /* Sending the datagram */
  if (sendto (s, datagram, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof (sin)) == ERROR)
  {
    log_msg (error_messages[E_SENDING_DATAGRAM]);
    return (ERROR);
  }
  
  return (OK);
}

int get_neighbor_addr (FILE *file, char *addr)
{
  unsigned nb_dots = 0,
	   nb_char = 0;
  int i;
  
  if (file == NULL)
    return (E_NO_NEIGHBOR_FILE);

  if (addr == NULL)
    return (E_GET_NEIGHBOR_ADDR);
  
  for (i = 0; i < 16; i++)
  {
    if ((fread (&addr[i], 1, 1, file)) != 1)
    {
      if (ferror (file))		/* error while reading file */
        return (E_GET_NEIGHBOR_ADDR);	
      return (RATD_EOF);		/* end of file is reached */
    }
    nb_char++;
    if (addr[i] == '.')
      nb_dots++;
    else if ((addr[i] != '\n') && (addr[i] != ' ') && ((addr[i] < '0') || (addr[i] > '9')))
        return (E_INVAL_ADDR); 
    if ((addr[i] == '\n') || (addr[i] == ' '))
    {
      if ((nb_dots != 3) || (nb_char < 7))
        return (E_INVAL_ADDR);		/* address is invalid */
      addr[i] = '\0';
      return (OK);
    }
  }
  
  return (E_INVAL_ADDR);  
}

//=========================================================================//
// Hash function
// Based on the gbf - Generalized Bloom Filter implementation
// by Rafael P. Laufer <rlaufer@gta.ufrj.br>
//=========================================================================//
unsigned hash (unsigned fid, unsigned x)
{
  unsigned long long c[4], d[4];
  unsigned p, m;

  //----- Defining the hash function parameters -----//
  c[0] = 1;
  d[0] = 2;

  c[1] = 3;
  d[1] = 4;

  c[2] = 5;
  d[2] = 6;

  c[3] = 7;
  d[3] = 8;

  //----- Defining the filter size and the prime number used -----//
  p = 4294967291;	
  m = 38*8;		/* filter size in bits */

  //--------------------------------------------------------------------//
  // Given a key x, the hash function returns            	        //
  // h_i(x) = ((c[i]*x + d[i]) mod p) mod m                             //
  //--------------------------------------------------------------------//	
  return (((c[fid]*x + d[fid]) % p) % m);
}

//=========================================================================//
// Function to verify affiliation of a neighbor to the filter
// Based on the gbf - Generalized Bloom Filter implementation
// by Rafael P. Laufer <rlaufer@gta.ufrj.br>
//=========================================================================//
int is_in_filter (unsigned x, unsigned char *bitArray)
{ 
  unsigned char	mask;
  unsigned char bits_set[38];	/* array that keeps track of the bits set	*/
  unsigned char bits_reset[38]; /* array that keeps track of the bits reset	*/
  unsigned	h;
  unsigned	*h_k0;
  unsigned	same	 = 0;
  unsigned	inverted = 0;
  unsigned	k0	 = 2;	/* k0 = number of hash functions that reset bits */
  unsigned	k1	 = 2;	/* k1 = number of hash functions that set bits	 */
  unsigned	i, j;

  memset (&bits_set, 0, 38);
  memset (&bits_reset, 0, 38);
  
  h_k0 = (unsigned *) calloc (k0, sizeof (unsigned));
	
  //----- Checking bits in zero -----//
  for (i = 0; i < k0; i++)
  {
    h = hash (k1+i, x);
    h_k0[i] = h;
    mask = 0x80 >> (h % 8);
    if ((bitArray[(unsigned)h/8] & mask) && (!(bits_set[(unsigned)h/8] & mask)))
    {
      inverted++;
      break;
    }
  }

  //----- Checking bits in one -----//
  for (i = 0; i < k1; i++)
  {
    h = hash (i,x);
    mask = 0x80 >> (h % 8);
    if (!(bitArray[(unsigned)h/8] & mask))
    {
      for (j = 0; j < k0; j++)
	if (h == h_k0[j])
	  same = 1;
      if (same == 1)
      { 
	same = 0;
	continue;
      }
      else
	if (!(bits_reset[(unsigned)h/8] & mask))
	{
	  inverted++;
	  break;
	}
    }
  }
	
  free (h_k0);

  if (inverted)
    return (0);
    
  return (1);
}

void process_packet (unsigned char *useless, const struct pcap_pkthdr *packet_hdr,
		     const unsigned char *packet)
{
  unsigned	     i;
  char		     route_filename[16];
  FILE		     *route_file;
  unsigned char	     temp[4];
  short int	     have_neighbor;		/* used like boolean	*/
  char		     is_src_host;		/* used like boolean	*/
  int		     ret;
  
  if (node_type == INITIAL_NODE)
  {
    /* Writing route in route file */
    snprintf (route_filename, 16, "/ratd/route.%03u", nb_routes++); 
    route_file = fopen (route_filename, "w");
    if (route_file == NULL)
      log_msg (error_messages[E_OPEN_ROUTE_FILE]);
    fprintf (route_file, "RATD Daemon Route File\n=======================\n\n");
    fprintf (route_file, "Route:\n\n");

    for (i = 85; (i < PACKET_SIZE) && (!is_null ((unsigned char *) &packet[i])); i +=4)
    {
      memcpy (&temp[0], &packet[i], 4);
      fprintf (route_file, "%s\n", inet_ntoa (*((struct in_addr *) &temp[0])));
    }
    fclose (route_file);  
  }
     
  if (node_type == INTERMEDIATE_NODE)
  {
    /* Saving the new source address in network byte order */
    memcpy (&src_addr, &packet[28], 4);

    /* Note that the first argument (destination address) in is_in_filter()
     * must be in host byte order						*/
    for (i = 0, have_neighbor = 0; i < nb_neighbors; i++)
    {
      ret = verify_host_addr (src_addr, neighbors_array[i], &is_src_host);
      if (ret != OK)
        log_msg (error_messages[ret]);

      if ((!is_src_host) &&
          (is_in_filter (ntohl (inet_addr (neighbors_array[i])), (unsigned char *) &packet[38])))
      { 
        have_neighbor = 1;
        if (send_packet (neighbors_array[i], (unsigned char *) packet, REQUEST_ROUTE) == ERROR)
          log_msg (error_messages[E_SEND_REQUEST_ROUTE_PACKET]);
      }
    }

    if (!have_neighbor)
    {
      memcpy (&temp[0], &packet[85], 4);
      if (send_packet (inet_ntoa (*((struct in_addr *) &temp[0])),
		       (unsigned char *) packet, ROUTE_REPLY) == ERROR)
        log_msg (error_messages[E_SEND_ROUTE_REPLY_PACKET]);
    }
  }
}
