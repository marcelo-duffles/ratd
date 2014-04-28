//===========================================================================//
// functions.h - header file of functions.c
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

#ifndef _FUNCTIONS_H_
#define _FUNCTIONS_H_

#include <sys/socket.h>       
#include <netinet/in.h>       
#include <netinet/ip.h>       
#include <netinet/ip_icmp.h>  
#include <netdb.h>
#include <pcap.h>


//====================================================================//
// Setting constants
//====================================================================//

/* Error constants */
#define RATD_EOF			-2
#define ERROR				-1
#define OK				0
#define E_CREATING_CHILD_SESSION	1
#define E_CHANGING_DIRECTORY		2
#define E_CLOSING_STANDARD_FILES	3
#define E_NO_PACKET			4
#define E_UNKNOWN_PROTO_ICMP		5
#define E_OPENING_SOCKET		6
#define E_IP_HEADER			7
#define E_SENDING_DATAGRAM		8
#define E_INVALID_HOST			9
#define E_OPEN_NEIGHBOR_FILE		10
#define E_NO_NEIGHBOR_FILE		11
#define E_SEND_PACKET			12
#define E_BUILD_PACKET			13
#define E_LOG_MSG			14
#define E_GETHOSTNAME			15
#define E_GETHOSTBYNAME			16
#define E_GET_NEIGHBOR_ADDR		17
#define E_INVAL_ADDR			18
#define E_OPEN_ROUTE_FILE		19
#define E_SEND_ROUTE_REPLY_PACKET	20
#define E_SEND_REQUEST_ROUTE_PACKET	21
#define E_VERIFY_HOST_ADDR		22


/* the size of the option gbf field */
#define OPTION_GBF_SIZE 40

/* number of addresses in packet data */
#define NB_OF_ADDRESSES 50

/* data size */
#define DATA_SIZE (NB_OF_ADDRESSES*4 +1)

/* total size of the packet */
#define PACKET_SIZE	sizeof(struct ip)	+\
			sizeof(struct icmphdr)	+\
			OPTION_GBF_SIZE		+\
			DATA_SIZE

/* index of FLAG option in packet data */
#define FLAG_INDEX	sizeof (struct ip) + OPTION_GBF_SIZE + sizeof (struct icmphdr)

/* node types values */
#define INITIAL_NODE		'i'
#define INTERMEDIATE_NODE	't'

/* flags in packet data */
#define REQUEST_ROUTE		1
#define ROUTE_REPLY		2

/* number of arguments of main program */
#define NB_ARGS			2

/* filters used to select the captured packet */
#define ECHO_FILTER		"ip[20:2] = 0x9928 and ip[62:2] = 0xc4ff"
#define REQUEST_ROUTE_FILTER	"icmp[icmptype] = icmp-echoreply and ip[20:2] = 0x9928 and ip[68] = 1"
#define ROUTE_REPLY_FILTER	"icmp[icmptype] = icmp-echoreply and ip[20:2] = 0x9928 and ip[68] = 2"

/* mode used to capture packets */
#define NO_PROMISCUOUS_MODE	0


//====================================================================//
// Global variables
//====================================================================//
extern pcap_t	*pkt_descr;		/* packet capture descriptor	*/
extern char	*error_messages[];	/* contains the error messages  */
extern int      node_type;		/* initial or intermediate node */
extern unsigned nb_routes;		/* total number of routes	*/
extern unsigned	src_addr;		/* source address		*/
extern unsigned	nb_neighbors;		/* number of neighbors	   	*/
extern char     *neighbors_array[300];	/* array of neighbors		*/


//====================================================================//
// Secundary functions prototypes
//====================================================================//
unsigned log_msg (char *message);
unsigned short csum (unsigned short *buf, int nwords);
int verify_host_addr (unsigned host, char *addr, char *bool);
int get_neighbor_addr (FILE *file, char *addr);
unsigned hash (unsigned function_id, unsigned address);
int is_in_filter (unsigned address, unsigned char *bloom_filter);
int send_packet (char *dest_addr, unsigned char *packet_data, unsigned char flag);
void process_packet (unsigned char *useless, const struct pcap_pkthdr *packet_hdr,
		     const unsigned char *packet);
int build_packet (struct sockaddr_in *sin, char *datagram, struct ip **iph,
	          struct icmphdr **icmph, struct hostent *host,
		  unsigned char *packet_data, unsigned char flag);

#endif /* _FUNCTIONS_H_ */
