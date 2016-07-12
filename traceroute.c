// Miroslawa Szewczyk, 241752
#include <sys/types.h>
#include <unistd.h>
#include "request_receive.h"

#define CLOCK_GETTIME(timespec_ptr) { if (gettimeofday(timespec_ptr, NULL) == -1) { ERROR ("gettime"); } }

int check_ownership(struct icmp* icmp_received, int id, int seq)
{
  return icmp_received->icmp_id == id && icmp_received->icmp_seq == seq;
}

int main (int argc, char** argv)
{
	if (argc != 2) { printf ("Usage: ./traceroute <addr>\n"); exit(1); }

  make_socket();

  printf("Sending to %s\n", argv[1]);

  char* receiver = argv[1];
	// Adres do ktorego bedziemy wysylac komunikat ICMP
  prepare_address(receiver);

  int process_num = getpid();

  int shall_pass = 1;

  for (int i = 1; shall_pass && i < 31; ++i)
  {
    printf("\t%i.\t", i);
    prepare_icmp_packet(process_num     // dobry pomysl: ustawic to na identyfikator procesu
                        , i             // kolejny numer w ramach jednego icmp_id
                        , i             // ttl
        );

    struct timeval times[4];
    CLOCK_GETTIME (&times[0]);

    for (int j = 0; j < 3; ++j)
    {
      // Wysyłamy jakis datagram do zdalnego serwera
      send_packet();
    }

    int timed_out = 1;

    char senders[3][20];

    for (int j = 0; timed_out && j < 3;)
    {
      struct packet_info packet;
      packet.timed_out = 0;
      receive_and_analyze_packet(&packet);


      if(packet.timed_out == 1) {

        printf("%20s\t", "*");
        timed_out = 0;

      } else {

        int ours = 0;

        print_bytes (ICMP_HEADER_LEN);

        // Pierwszy interesujacy typ pakietu to odpowiedzi TIME_EXCEEDED
        if (packet.icmp_packet.icmp_type == ICMP_TIME_EXCEEDED &&
          packet.icmp_packet.icmp_code == ICMP_EXC_TTL) {

          struct icmp original_icmp;
          analyze_time_exceeded(&original_icmp);
          ours = check_ownership(&original_icmp, process_num, i);
        }

        // Drugi interesujacy typ pakietow to odpowiedzi na echo
        if (packet.icmp_packet.icmp_type == ICMP_ECHOREPLY) {

          // Odbiorca odsyla nam komunikat ECHO REPLY (prawdopodobnie
          // w odpowiedzi na nasze ECHO REQUEST). Zeby to sprawdzic, nalezy
          // obejrzec pola id i seq pakietu ICMP.
          ours = check_ownership(&packet.icmp_packet, process_num, i);
          if(ours) {
            shall_pass = 0;
          }
        }

        if (ours) {
          inet_ntop(AF_INET, &(packet.sender.sin_addr), senders[j], sizeof(senders[j]));

          CLOCK_GETTIME (&times[j+1]);
          ++j;
        }

      }
    }

    int sum = 0, count = 0;
    // NOTE: will only write if received all 3 responses.
    if (timed_out != 0 ) {
      printf("%20s\t", senders[0]);
      if(strcmp(senders[0], senders[1]) > 0) {
        printf("%20s\t", senders[1]);
      }
      if(strcmp(senders[0], senders[2]) > 0 && strcmp(senders[1], senders[2]) > 0) {
        printf("%20s\t", senders[2]);
      }

      // NOTE: takes average of all responses, without distinguishing their source
      for (int j = 1; j < 4; ++j)
      {
        if(times[j].tv_sec != 0) {
          sum += (times[j].tv_sec - times[0].tv_sec) * 1000000 + times[j].tv_usec - times[0].tv_usec;
          ++count;
        }

      }

    }
    if(count == 3) {
      int avg = sum / count;
      if (avg < 1000) {
        printf("%i us", avg);
      } else {
        printf("%i ms", avg / 1000);
      }
    } else {
      printf("???");
    }
    printf("\n");
  }

	return 0;
}
