#include <stdio.h>
#include <signal.h>
#include <threads.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>
#include <dirent.h>
#include <errno.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include "common/BufferRing.h"

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#define EVENT_SIZE		(sizeof(struct inotify_event))
#define EVENT_BUF_LEN	(1024 * (EVENT_SIZE + 16))
#define max(a, b)		((a) > (b) ? (a) : (b))
#define MAX_RETRIES		5
#define RECONNECT_DELAY 3
//
typedef char	*pChar;
// Параметры мониторинга
typedef struct {
	int fd;			// inotify descriptor
	int *watches;	// Массив watch-дескрипторов
	pChar *pathes;  // Массив путей слежения
	size_t count;	// Количество директорий в мониторинге
} InotifyMonitor;
// Данные события
typedef struct LogValue {
	time_t time;			// Время события
	uint32_t mask;		// Маска изменений
	unsigned char path[PATH_MAX];				// Путь к файлу
	unsigned char sha256[SHA256_DIGEST_LENGTH]; // hase
} LogValue;
// Узел очереди событий
typedef struct Node {
	LogValue value;
	struct Node *next;
} Node;
// Очередь событий
typedef struct {
	Node *head, *tail;	// Голова, хвост
	mtx_t mutex;			// Мутех для синхронизации между потоками
	cnd_t not_empty;		// Сигнальная переменная
	atomic_int initialized; // Текущее состояние очереди (создана/освобождена)
} Queue;
//

atomic_int running = 0; // Состояние процесса
char notifyPath[PATH_MAX] = {0}; // Путь к корневому каталогу мониторинга
int scanTimeout = 1; // Время сканирования
char host[64] = {"127.0.0.1"}; // Адрес сервера
int port = 5555; // Порт TCP
Queue notifyQueue; // Очередь событий
InotifyMonitor monitor = {0}; // Параметры монитора
// Вычисление sha256 для файла
void sha256_file(const char *filename,unsigned char hash[SHA256_DIGEST_LENGTH]) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	unsigned char buffer[4096];
	size_t bytesRead;
	FILE *file = fopen(filename, "rb");
	if (!file) {
		memset(hash,0,SHA256_DIGEST_LENGTH);
		return;
	}

	while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		SHA256_Update(&ctx, buffer, bytesRead);
	}
	fclose(file);
	SHA256_Final(hash, &ctx);
}
// Инициализация очереди событий
void queue_init(Queue *q) {
	q->head = q->tail = NULL;
	mtx_init(&q->mutex, mtx_plain);
	cnd_init(&q->not_empty);
	atomic_store(&q->initialized,1);
}
// Уничтожение очереди событий
void queue_destroy(Queue *q) {
	while (q->head) {
		Node *temp = q->head;
		q->head = q->head->next;
		free(temp);
	}
	mtx_destroy(&q->mutex);
	cnd_destroy(&q->not_empty);
}
// Остановка ожидания нового элемента
void queue_halt(Queue *q) {
	int i = atomic_load(&q->initialized);
	if (i) {
		atomic_store(&q->initialized,0);
		cnd_signal(&q->not_empty);
	}
}
// Провера на работоспособность
uint8_t queue_is_initialized(Queue *q){
	return atomic_load(&q->initialized);
}
// Помещение события в очередь
void queue_push(Queue *q, uint32_t mask,char *path,unsigned char hash[SHA256_DIGEST_LENGTH]) {
	Node *new_node = malloc(sizeof(Node));
	if (!new_node) {
		perror("Ошибка выделения памяти");
		exit(1);
	}
	memset(new_node,0,sizeof(Node));
	new_node->value.time = time(0);
	new_node->value.mask = mask;
	strcpy(new_node->value.path,path);
	memcpy(new_node->value.sha256,hash,SHA256_DIGEST_LENGTH);
	new_node->next = NULL;

	mtx_lock(&q->mutex);

	if (q->tail) {
		q->tail->next = new_node;
		q->tail = new_node;
	} else {
		q->head = q->tail = new_node;
	}
	cnd_signal(&q->not_empty); // будильник
	mtx_unlock(&q->mutex);
}
// Извлечение события из очереди
LogValue *queue_pop(Queue *q,LogValue *val) {
	int i = 1;
	mtx_lock(&q->mutex);
	while (!q->head) {
		i = atomic_load(&q->initialized);
		if ( !i ){
			break;
		}
		cnd_wait(&q->not_empty, &q->mutex);
	}
	if ( !i ) {
		mtx_unlock(&q->mutex);
		return val;
	}

	Node *temp = q->head;
	*val = temp->value;
	q->head = q->head->next;
	if (!q->head) {
		q->tail = NULL;  // Очередь опустела
	}

	free(temp);
	mtx_unlock(&q->mutex);
	return val;
}
// Вывод параметорв использования программы
void usage() {
	printf("usage: test_client [-d path] директория сканирования\n"
		   "[-t sec] частота сканирования в сек\n"
		   "[-i ip] сервера\n"
		   "[-p порт] сервера\n");
}
// Добавление мониторинга единичного каталога
void add_watch(InotifyMonitor *monitor, const char *path) {
	int wd = inotify_add_watch(monitor->fd, path, IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
	if (wd == -1) {
		perror("inotify_add_watch");
		return;
	}
	monitor->watches = realloc(monitor->watches, (monitor->count + 1) * sizeof(int));
	monitor->watches[monitor->count] = wd;
	monitor->pathes = realloc(monitor->pathes, (monitor->count + 1) * sizeof(pChar));
	monitor->pathes[monitor->count] = malloc(strlen(path) + 1);
	strcpy(monitor->pathes[monitor->count++],path);
	printf("Добавлен мониторинг: %s (wd=%d)\n", path, wd);
}
// Добавление мониторинга калаога и его вложений
void add_watch_recursive(InotifyMonitor *monitor, const char *path) {
	DIR *dir = opendir(path);
	if (!dir) {
		perror("opendir");
		return;
	}

	int wd = inotify_add_watch(monitor->fd, path, IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
	if (wd == -1) {
		perror("inotify_add_watch");
		closedir(dir);
		return;
	}

	monitor->watches = realloc(monitor->watches, (monitor->count + 1) * sizeof(int));
	monitor->watches[monitor->count] = wd;
	monitor->pathes = realloc(monitor->pathes, (monitor->count + 1) * sizeof(pChar));
	monitor->pathes[monitor->count] = malloc(strlen(path) + 1);
	strcpy(monitor->pathes[monitor->count++],path);

	printf("Добавлен мониторинг: %s (wd=%d)\n", path, wd);

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type == DT_DIR) {
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;

			char subdir[PATH_MAX];
			snprintf(subdir, sizeof(subdir), "%s/%s", path, entry->d_name);
			add_watch_recursive(monitor, subdir);
		}
	}
	closedir(dir);
}
// Освобождение ресурсов из под данных мониторига
void cleanup_monitor(InotifyMonitor *monitor) {
	for (size_t i = 0; i < monitor->count; i++) {
		inotify_rm_watch(monitor->fd, monitor->watches[i]);
		free(monitor->pathes[i]);
	}
	free(monitor->pathes);
	free(monitor->watches);
	if(monitor->fd != -1) {
		close(monitor->fd);
	}
}
// Определение пути мониторинга по его дискриптору
char *get_path_by_watch(InotifyMonitor *monitor,int wd){
	for(int i = 0; i < monitor->count; i++) {
		if(monitor->watches[i] == wd) {
			return monitor->pathes[i];
		}
	}
	return 0;
}
// Проверка является ли объект каталогом
int is_directory(const char *path) {
	struct stat statbuf;
	if (stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode))
		return 1;
	return 0;
}
// Поток мониторинга
int notifyTask(void *arg) {
	char buffer[EVENT_BUF_LEN];

	printf("notifyTask : %s\n",notifyPath);
	if( atomic_load(&running) ){
		if(scanTimeout = 0) { // При нулевой задержки используются нотификации в блокирующем режиме
			monitor.fd = inotify_init();
		}
		else {
			monitor.fd = inotify_init1(IN_NONBLOCK);
		}
		if (monitor.fd < 0) {
			perror("Ошибка inotify_init");
			return EXIT_FAILURE;
		}
		add_watch_recursive(&monitor,notifyPath);
	}
	else {
		return EXIT_FAILURE;
	}
	struct timespec timeout;
	timeout.tv_sec = scanTimeout;
	while ( atomic_load(&running) ) {
		int length = read(monitor.fd, buffer, EVENT_BUF_LEN);
		if (length < 0) {
			if(scanTimeout != 0) {
				thrd_sleep(&timeout,0);
			}
			continue;
		}
		int i = 0;
		while (i < length) {
			struct inotify_event *event = (struct inotify_event *) &buffer[i];
			if (event->len) {
				char *root = get_path_by_watch(&monitor,event->wd);
				if( !root ){
					perror("Неопределенный номер монитора");
				}
				else {
					char path[PATH_MAX];
					unsigned char hash[SHA256_DIGEST_LENGTH];
					if(strcmp(event->name,"server.log") != 0){
						snprintf(path, sizeof(path), "%s/%s", root, event->name);
						sha256_file(path,hash);
						queue_push(&notifyQueue,event->mask,path,hash);
						if (event->mask & IN_CREATE) {
							if (is_directory(path)) {
								printf("Новая папка: %s -> добавляем в мониторинг\n", path);
								add_watch(&monitor, path);
							}
						}
					}
				}
			}
			i += EVENT_SIZE + event->len;
		}
	}
	cleanup_monitor(&monitor);
	return EXIT_SUCCESS;
}
// Подключение к серверу
int connect_to_server(struct sockaddr_in *server_addr) {
	int sock;
	for (int attempt = 1; attempt <= MAX_RETRIES && atomic_load(&running); attempt++) {
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock == -1) {
			perror("Ошибка создания сокета");
			return -1;
		}

		if (connect(sock, (struct sockaddr*)server_addr, sizeof(*server_addr)) == 0) {
			fprintf(stderr,"Подключено к серверу.\n");
			return sock;
		}

		perror("Ошибка подключения");
		close(sock);
		fprintf(stderr,"Повторная попытка подключения (%d/%d) через %d секунд...\n",
			   attempt, MAX_RETRIES, RECONNECT_DELAY);
		thrd_sleep(&(struct timespec){.tv_sec = RECONNECT_DELAY}, NULL);
	}

	fprintf(stderr,"Не удалось подключиться после %d попыток.\n", MAX_RETRIES);
	return -1;
}
// Проверка наличия подключения к серверу
int check_connection(int sock) {
	if(sock == -1) return 0;
	char buf;
	int result = recv(sock, &buf, 1, MSG_PEEK|MSG_DONTWAIT);
	if (result == 0) {
		fprintf(stderr,"Сервер закрыл соединение.\n");
		return 0;
	}
	if (result == -1 && errno == ECONNRESET) {
		fprintf(stderr,"Соединение сброшено сервером.\n");
		return 0;
	}
	return 1;
}
// Поток отправки сообщений на сервер
int senderTask(void *arg){
	LogValue val;
	cmp_ctx_t cmp = {0};
	BufferRing messages;
	uint8_t buffer[sizeof(LogValue) + sizeof(uint32_t) + 4];
	int data_size;
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
		atomic_store(&running,0);
		perror("Неверный адрес");
		return EXIT_FAILURE;
	}
	int sock = connect_to_server(&server_addr);
	if (sock == -1) {
		atomic_store(&running,0);
		return EXIT_FAILURE;
	}
	cmp_init_buffer_ring(&cmp,&messages);
	while ( atomic_load(&running) ) {
		queue_pop(&notifyQueue,&val);
		if(!queue_is_initialized(&notifyQueue)) {
			break;
		}
		cmp_write_u64(&cmp,val.time);
		cmp_write_u32(&cmp,val.mask);
		cmp_write_str(&cmp,val.path,strlen(val.path));
		cmp_write_bin(&cmp,val.sha256,SHA256_DIGEST_LENGTH);
		data_size = buffer_ring_available(&messages);
		if(read_bytes(buffer,data_size,&messages)) {
			while (atomic_load(&running) && !check_connection(sock)){
				close(sock);
				sock = connect_to_server(&server_addr);
			}
			if(sock != -1) {
				send(sock, buffer, data_size, 0);
			}
		}

		char event_type[64] = "UNKNOWN";
		if (val.mask & IN_CREATE) strcpy(event_type, "CREATED");
		if (val.mask & IN_DELETE) strcpy(event_type, "DELETED");
		if (val.mask & IN_MODIFY) strcpy(event_type, "MODIFIED");
		if (val.mask & IN_MOVED_TO) strcpy(event_type, "MOVED TO");
		if (val.mask & IN_MOVED_FROM) strcpy(event_type, "MOVED FROM");

		fprintf(stderr,"📂 %s: %s ", event_type, val.path);
		for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++)
			fprintf(stderr,"%02x", val.sha256[i]);
		fprintf(stderr,"\n");

	}
	if(sock != -1) {
		close(sock);
	}
	return EXIT_SUCCESS;
}
// Обработка сигналов SIGINT? SIGKILL
void signal_function(int f){
	atomic_store(&running,0);
	if(monitor.fd != -1) {
		close(monitor.fd);
		monitor.fd = -1;
	}
	queue_halt(&notifyQueue);
	printf("signal\n");
}
// Точка входа в программу
int main(int argc,char *argv[]) {
	thrd_t threadNotify,threadSender;
	getcwd(notifyPath,sizeof(notifyPath));
	for (int i = 1; i < argc; i++) {
		if (i + 1 < argc) {
			if (strcmp(argv[i], "-d") == 0) {
				strcpy(notifyPath,argv[i + 1]);
				i++;
			}
			else {
				if (strcmp(argv[i], "-t") == 0) {
					scanTimeout = max(0,atoi(argv[i + 1]));
					i++;
				}
				else {
					if (strcmp(argv[i], "-i") == 0) {
						strcpy(host,argv[i + 1]);
						i++;
					}
					else {
						if (strcmp(argv[i], "-p") == 0) {
							port = atoi(argv[i + 1]);
							i++;
						}
						else {
							usage();
							return -1;
						}
					}
				}
			}
		}
		else {
			usage();
			return -1;
		}
	}
	if(!is_directory(notifyPath)) {
		printf("%s не является каталогом\n",notifyPath);
		return -1;
	}
	printf("path = %s, timeout = %d, server = %s:%d",notifyPath,scanTimeout,host,port);
	signal(SIGINT, signal_function);
	signal(SIGKILL, signal_function);

	queue_init(&notifyQueue);

	atomic_store(&running,1);
	thrd_create(&threadNotify, notifyTask, 0);
	thrd_create(&threadSender, senderTask, 0);

	thrd_join(threadNotify, NULL);
	thrd_join(threadSender, NULL);

	queue_destroy(&notifyQueue);
	printf("exit\n");
	return 0;
}
