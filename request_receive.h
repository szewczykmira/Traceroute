// Miroslawa Szewczyk, 241752  
#ifndef __REQUEST_RECEIVE_H
#define __REQUEST_RECEIVE_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include "sockwrap.h"
#include "icmp.h"

struct packet_info
{
  struct sockaddr_in sender;
  struct icmp icmp_packet;
  bool timed_out;
};

int sockfd;
struct sockaddr_in remote_address;
struct icmp icmp_packet;

unsigned char 	buffer[IP_MAXPACKET+1];
unsigned char* 	buffer_ptr;
int				remaining_packet_data;

void make_socket();
void prepare_address(char* addr);
void prepare_icmp_packet(int id, int seq, int ttl);
void send_packet();
void print_bytes (int count);
void receive_data(struct packet_info* packet);
void analyze_ip();
void analyze_time_exceeded(struct icmp* original_icmp);
void analyze_icmp();
void receive_and_analyze_packet(struct packet_info* packet);

#endif
