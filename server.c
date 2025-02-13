#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/inotify.h>
#include "common/BufferRing.h"

#ifndef SHA256_DIGEST_LENGTH
	#define SHA256_DIGEST_LENGTH 32
#endif
#define min(a, b)		((a) < (b) ? (a) : (b))

uint8_t running = 0;
int port = 5555;
int server_fd = -1;
int client_socket = -1;
static const char *eventTypeNames[] = {"UNKNOWN","CREATED","DELETED","MODIFIED","MOVED TO","MOVED FROM"};

void usage() {
	printf("usage: notify_server [-p порт] сервера\n");
}
// Обработка сигналос INT,KILL
void signal_function(int f){
	running = 0;
	if( server_fd != -1) {
		shutdown(server_fd,2);
	}
	if( client_socket!= -1) {
		shutdown(client_socket,2);
	}
	printf("signal\n");
}
// Сообщение об ошибке пакета
void bad_packet(BufferRing *b) {
	perror("Ошибка пакета");
	buffer_ring_clear(b);
}
// Текстовое название события
const char *get_event_type_name(uint32_t mask){
	const char *res = eventTypeNames[0];
	if (mask & IN_CREATE) res = eventTypeNames[1];
	if (mask & IN_DELETE) res = eventTypeNames[2];
	if (mask & IN_MODIFY) res = eventTypeNames[3];
	if (mask & IN_MOVED_TO) res = eventTypeNames[4];
	if (mask & IN_MOVED_FROM) res = eventTypeNames[5];
	return res;
}
// Преобразование битовой послетовательности в тествоую строку в hex
void hex_to_string(uint8_t *hex,int lenHex,char *buf,int lenBuf) {
	int offset = 0;
	for (unsigned int i = 0; i < lenHex && offset + 2 < lenBuf; i++){
		sprintf(buf + offset,"%02x", hex[i]);
		offset += 2;
	}
}
// Точка входа
int main(int argc,char *argv[]) {
	cmp_ctx_t cmp = {0};
	BufferRing messages;
	uint8_t buffer[PATH_MAX] = {0};
	struct sockaddr_in address;
	socklen_t addr_len = sizeof(address);
	uint64_t eventTime64;
	time_t eventTime;
	uint32_t eventMask;
	uint32_t pathLength;
	uint32_t shaLength;
	char path[PATH_MAX];
	uint8_t sha256[SHA256_DIGEST_LENGTH];
	struct tm *local;
	char tim_char[32];
	char sha256str[66];
	const char *eventTpe;
	char logFileName[PATH_MAX];
	FILE *logFile = {0};

	// Разбор параметров командной строки
	for (int i = 1; i < argc; i++) {
		if (i + 1 < argc) {
			if (strcmp(argv[i], "-p") == 0) {
				port = atoi(argv[i + 1]);
				i++;
			}
			else {
				usage();
				return -1;
			}
		}
		else {
			usage();
			return -1;
		}
	}
	// Установка обработчиков оств=ановки процесса
	signal(SIGINT, signal_function);
	signal(SIGKILL, signal_function);
	// Связь msgpack с циклическим буфером
	cmp_init_buffer_ring(&cmp,&messages);
	// Настройка сервера
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		perror("Ошибка создания сокета");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);

	if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
		perror("Ошибка привязки");
		close(server_fd);
		return EXIT_FAILURE;
	}
	if (listen(server_fd, 3) < 0) {
		perror("Ошибка прослушивания");
		close(server_fd);
		return EXIT_FAILURE;
	}

	printf("Сервер запущен и ждет подключений на порту %d...\n", port);
	sprintf(logFileName,"%s.log",argv[0]);
	logFile = fopen(logFileName,"w+t");
	if(!logFile){
		perror("Ошибка открытия лог-файла");
		close(server_fd);
		return EXIT_FAILURE;
	}
	// Основной цикл взаимодействия с клиентом
	running = 1;
	while(running) {
		client_socket = accept(server_fd, (struct sockaddr*)&address, &addr_len);
		if (client_socket < 0) {
			if( running ){
				perror("Ошибка принятия подключения");
			}
			continue;
		}
		// Обработчик сообщений
		while(running){
			ssize_t bytes_read = read(client_socket, buffer, PATH_MAX);
			if (bytes_read <= 0) {
				fprintf(stderr,"Клиент отключился.\n");
				break;
			}
			write_bytes(buffer,bytes_read,&messages);
			while (!buffer_ring_is_empty(&messages)){
				if(!cmp_read_u64(&cmp,&eventTime64)) {
					bad_packet(&messages);
					continue;
				}
				if(!cmp_read_u32(&cmp,&eventMask)) {
					bad_packet(&messages);
					continue;
				}
				if (!cmp_read_str_size(&cmp, &pathLength)) {
					bad_packet(&messages);
					continue;
				}
				memset(path,0,sizeof(path));
				if(!read_bytes(path,pathLength,&messages)){
					bad_packet(&messages);
					continue;
				}
				if(!cmp_read_bin_size(&cmp,&shaLength)){
					bad_packet(&messages);
					continue;
				}
				shaLength = min(SHA256_DIGEST_LENGTH,shaLength);
				memset(sha256,0,sizeof(sha256));
				if(!read_bytes(sha256,shaLength,&messages)){
					bad_packet(&messages);
					continue;
				}
				eventTime = (time_t)eventTime64;
				local = localtime(&eventTime);
				strftime(tim_char, sizeof(tim_char), "%d-%m-%Y %H:%M:%S", local);
				eventTpe = get_event_type_name(eventMask);
				hex_to_string(sha256,SHA256_DIGEST_LENGTH,sha256str,sizeof(sha256str));
				fprintf(logFile,"[%s]{\"type_of_event\":\"%s\","
					"\"file_name\":\"%s\",\"sha256\":\"%s\"}\n",tim_char,eventTpe, path, sha256str);
				fflush(logFile);
			}
		}
		close(client_socket);
		client_socket = -1;
	}
	// Выход
	if(logFile) {
		fclose(logFile);
	}
	if(client_socket != -1) {
		close(client_socket);
	}
	if( server_fd != -1) {
		close(server_fd);
	}
	fprintf(stderr,"exit server\n");
	return 0;
}
