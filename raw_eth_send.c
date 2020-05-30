#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	int arp_header_len = 0;
	char buffer[BUFFER_SIZE];
	unsigned char data[MAX_DATA_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);

	unsigned char buffer_arp[6];
	unsigned char ip_orig[] = {192, 168, 56, 1};
	unsigned char ip_dest[] = {192, 168, 56, 1};

	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);
	memset(data, 0, MAX_DATA_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */	
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);

	/**************************************/
	/*
	// Obtem uma mensagem do usuario
	printf("Digite a mensagem: ");
	scanf("%[^\n]s", data);

	// Preenche o campo de dados
	memcpy(buffer + frame_len, data, strlen(data));
	frame_len += strlen(data) + 1;
	*/

	/* Colocando interface de HW Ethernet */
	memset(buffer_arp, 0, sizeof(buffer_arp));
	buffer_arp[1] = 1;
	memcpy(data, buffer_arp, 2);
	arp_header_len += 2;

	/* Protocolo */
	memset(buffer_arp, 0, sizeof(buffer_arp));
	buffer_arp[0] = 0x08; buffer_arp[1] = 0x00;
	memcpy(data + arp_header_len, buffer_arp, 2);
	arp_header_len += 2;

	/* Tamanho do endereço de Hardware */
	memset(buffer_arp, 0, sizeof(buffer_arp));
	buffer_arp[0] = 6;
	memcpy(data + arp_header_len, buffer_arp, 1);
	arp_header_len += 1;

	/* Tamanho do endereço do protocolo alto nível */
	memset(buffer_arp, 0, sizeof(buffer_arp));
	buffer_arp[0] = 4;
	memcpy(data + arp_header_len, buffer_arp, 1);
	arp_header_len += 1;

	/* Tipo da mensagem 0001 request 0002 response */
	memset(buffer_arp, 0, sizeof(buffer_arp));
	buffer_arp[0] = 0x00; buffer_arp[1] = 0x01;
	memcpy(data + arp_header_len, buffer_arp, 2);
	arp_header_len += 2;

	/* Endereço MAC do nó origem */
	memcpy(data + arp_header_len, if_mac.ifr_hwaddr.sa_data, 6);
	arp_header_len += 6;

	/* Endereço IP do nó origem */
	memcpy(data + arp_header_len, ip_orig, 4);
	arp_header_len += 4;

	/* Endereço MAC do nó destino */
	memcpy(data + arp_header_len, dest_mac, 6);
	arp_header_len += 6;

	/* Endereço IP do nó destino */
	memcpy(data + arp_header_len, ip_dest, 4);
	arp_header_len += 4;

	/* Preenche o campo de dados */
	memcpy(buffer + frame_len, data, arp_header_len);
	frame_len += arp_header_len;

	printf("Header Length : %d\n", arp_header_len);

	for(int i = 0; i < arp_header_len; i++)
	{
		printf("%u\n",data[i]);
	}

	/***************************************/

	/* Envia pacote */
	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}

	printf("Pacote enviado.\n");

	close(fd);
	return 0;
}
