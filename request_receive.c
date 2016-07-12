// Miroslawa Szewczyk, 241752
#include "request_receive.h"

int sockfd;
struct sockaddr_in remote_address;
struct icmp icmp_packet;

unsigned char 	buffer[IP_MAXPACKET+1];
unsigned char* 	buffer_ptr;
int				remaining_packet_data;

void make_socket()
{
	sockfd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

void prepare_address(char* addr)
{
	bzero (&remote_address, sizeof(remote_address));
	remote_address.sin_family	= AF_INET;
	inet_pton(AF_INET, addr, &remote_address.sin_addr);
}

void prepare_icmp_packet(int id, int seq, int ttl)
{
	icmp_packet.icmp_type = ICMP_ECHO;
	icmp_packet.icmp_code = 0;
	icmp_packet.icmp_id = id;
	icmp_packet.icmp_seq = seq;
	icmp_packet.icmp_cksum = 0;
	icmp_packet.icmp_cksum = in_cksum((u_short*)&icmp_packet, 8, 0);

	Setsockopt (sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
}

void send_packet()
{
	// Wysylamy tylko naglowek, bez dodatkowych danych
	Sendto(sockfd, &icmp_packet, ICMP_HEADER_LEN, 0, &remote_address, sizeof(remote_address));
}

// Drukuje count bajtow zaczynajac od miejsca wskazywanego przez globalna
// zmienna buffer_ptr, po wykonaniu buffer_ptr zwieksza sie o count.
// Dodatkowo zmniejsza zmienna remaining_packet_data o count.
void print_bytes (int count)
{
	for (int i=0; i<count; i++) {
    buffer_ptr++; remaining_packet_data--;
	}
}

void receive_data(struct packet_info* packet)
{
  socklen_t sender_len = sizeof(struct sockaddr_in);
  buffer_ptr = buffer;
  struct pollfd fd;
  fd.fd = sockfd;
  fd.events = POLLIN;
  int ret = poll(&fd, 1, 1000);
  if (ret == -1) {
    ERROR ("Poll error");
  }
  if (ret == 0) {
    packet->timed_out = 1;
  } else {
    remaining_packet_data = Recvfrom (sockfd, buffer_ptr, IP_MAXPACKET,
                      0, &packet->sender, &sender_len);
  }
}

void analyze_ip()
{
  // Na poczatku bufora jest naglowek IP
  struct ip* packet = (struct ip*) buffer_ptr;
  print_bytes (packet->ip_hl * 4);
}

void analyze_time_exceeded(struct icmp* original_icmp)
{
  // Pakiet ICMP generowany w momencie zmniejszenia TTL do zera,
  // zawiera w danych kopie pakietu IP, ktoremu pole TTL spadlo do zera

  struct ip* packet_orig = (struct ip*) buffer_ptr;
  print_bytes (packet_orig->ip_hl * 4);

  assert(packet_orig->ip_p == IPPROTO_ICMP);
  // Ten pakiet zostal wygenerowany w odpowiedzi na pakiet IP:ICMP
  // (byc moze na nasz -- trzeba sprawdzic w tym celu pola id i seq)
  *original_icmp = *(struct icmp*) buffer_ptr;
}

void analyze_icmp(struct packet_info* packet)
{
  // Nastepnie na pewno jest ICMP enkapsulowany w pakiecie IP
  struct icmp* received_icmp_packet = (struct icmp*) buffer_ptr;

  packet->icmp_packet = *received_icmp_packet;
}


void receive_and_analyze_packet(struct packet_info* packet)
{
  receive_data(packet);

  analyze_ip();

  analyze_icmp(packet);
}
