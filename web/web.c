#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <time.h>
#include <sys/time.h>

#define POST 12
#define GET 13
#define VERSION 24
#define BUFSIZE 8096
#define ERROR 42
#define LOG 44
#define BAD_REQUEST 400
#define PROHIBIDO 403
#define NOENCONTRADO 404
#define NOACEPTABLE 406
#define NOIMPLEMENTADO 501
#define VERSION_NOTSUPPORTED 505

static char fich_badrequest[] = "errores/400.html";
static char fich_notfound[] = "errores/404.html";
static char fich_forbidden[] = "errores/403.html";
static char fich_notaccept[] = "errores/406.html";
static char fich_notimplemented[] = "errores/501.html";
static char fich_version[] = "errores/505.html";

struct
{
	char *ext;
	char *filetype;
} extensions[] = {
	{"gif", "image/gif"},
	{"jpg", "image/jpg"},
	{"jpeg", "image/jpeg"},
	{"png", "image/png"},
	{"ico", "image/ico"},
	{"zip", "image/zip"},
	{"gz", "image/gz"},
	{"tar", "image/tar"},
	{"htm", "text/html"},
	{"html", "text/html"},
	{0, 0}};

struct request
{
	char *tipo;
	char *archivo;
	char *protocolo;
	int cookieContador;
};
void parser_first_line(char *linea, struct request *pet)
{
	char *ptr;
	char *saveptr2;
	ptr = strtok_r(linea, " ", &saveptr2);
	pet->tipo = ptr;
	ptr = strtok_r(NULL, " ", &saveptr2);
	pet->archivo = ptr;
	ptr = strtok_r(NULL, "\r", &saveptr2);
	pet->protocolo = ptr;
}
int parser_cookie(char *cookie)
{
	char *numero = strrchr(cookie, '=') + 1;
	int	accesos = *numero - '0';
	return accesos;
}
void debug(int log_message_type, char *message, char *additional_info, int socket_fd)
{
	int fd;
	char logbuffer[BUFSIZE * 2];

	switch (log_message_type)
	{
	case ERROR:
		(void)sprintf(logbuffer, "ERROR: %s:%s Errno=%d exiting pid=%d", message, additional_info, errno, getpid());
		break;
	case BAD_REQUEST:
		// Enviar como respuesta 403 Forbidden
		(void)sprintf(logbuffer, "BAD-REQUEST: %s:%s", message, additional_info);
		break;
	case PROHIBIDO:
		// Enviar como respuesta 403 Forbidden
		(void)sprintf(logbuffer, "FORBIDDEN: %s:%s", message, additional_info);
		break;
	case NOENCONTRADO:
		// Enviar como respuesta 404 Not Found
		(void)sprintf(logbuffer, "NOT FOUND: %s:%s", message, additional_info);
		break;
	case NOACEPTABLE:
		// Enviar como respuesta 406 No ACEPTABLE
		(void)sprintf(logbuffer, "NOT ACCEPTED: %s:%s", message, additional_info);
		break;
	case NOIMPLEMENTADO:
		// Enviar como respuesta 501 No IMPLEMENTADO
		(void)sprintf(logbuffer, "NOT IMPLEMENTED: %s:%s", message, additional_info);
		break;
	case VERSION_NOTSUPPORTED:
		// Enviar como respuesta 505 No HTTP VERSION SOPORTADO
		(void)sprintf(logbuffer, "VERSION HTTP NOT SUPPORTED: %s:%s", message, additional_info);
		break;
	case LOG:
		(void)sprintf(logbuffer, " INFO: %s:%s:%d", message, additional_info, socket_fd);
		break;
	}

	if ((fd = open("webserver.log", O_CREAT | O_WRONLY | O_APPEND, 0644)) >= 0)
	{
		(void)write(fd, logbuffer, strlen(logbuffer));
		(void)write(fd, "\n", 1);
		(void)close(fd);
	}
}
void mandar_error(int error, int fd, struct request peticion)
{
	char buff_respuesta[BUFSIZE] = {0};
	char buff_fecha[256] = {0};
	char tamano[256] = {0};
	struct stat info_fichero;
	FILE *file;
	int extension = 9;
	time_t fecha = time(NULL);
	struct tm *now_tm;
	now_tm = gmtime(&fecha);
	strcat(buff_respuesta, "HTTP/1.1");
	switch (error)
	{
	case BAD_REQUEST:
		if (stat(fich_notfound, &info_fichero) < 0)
		{
			debug(NOENCONTRADO, "fichero no encontrado", "not found", fd);
		}
		debug(BAD_REQUEST, "peticion mal formada", "bad request", fd);
		file = fopen(fich_badrequest, "rb");
		strcat(buff_respuesta, " 400 Not Found\r\n");
		break;
	case NOENCONTRADO:
		if (stat(fich_notfound, &info_fichero) < 0)
		{
			debug(NOENCONTRADO, "fichero no encontrado", "not found", fd);
		}
		debug(NOENCONTRADO, "fichero no encontrado", "not found", fd);
		file = fopen(fich_notfound, "rb");
		strcat(buff_respuesta, " 404 Not Found\r\n");
		break;
	case PROHIBIDO:
		if (stat(fich_forbidden, &info_fichero) < 0)
		{
			debug(NOENCONTRADO, "fichero no encontrado", "not found", fd);
		}
		debug(PROHIBIDO, "fichero prohibido", "forbidden", fd);
		file = fopen(fich_forbidden, "r");
		strcat(buff_respuesta, " 403 Forbidden\r\n");
		break;
	case NOACEPTABLE:
		if (stat(fich_notaccept, &info_fichero) < 0)
		{
			debug(NOENCONTRADO, "fichero no encontrado", "not found", fd);
		}
		debug(NOACEPTABLE, "tipo de fichero no aceptado", "not accepted", fd);
		file = fopen(fich_notaccept, "r");
		strcat(buff_respuesta, " 406 Not Acceptable\r\n");
		break;
	case NOIMPLEMENTADO:
		if (stat(fich_notimplemented, &info_fichero) < 0)
		{
			debug(NOENCONTRADO, "fichero no encontrado", "not found", fd);
		}
		debug(NOIMPLEMENTADO, "peticion http no implementada", "not implemented", fd);
		file = fopen(fich_notimplemented, "r");
		strcat(buff_respuesta, " 501 Not Implemented\r\n");
		break;
	case VERSION_NOTSUPPORTED:
		if (stat(fich_version, &info_fichero) < 0)
		{
			debug(NOENCONTRADO, "fichero no encontrado", "not found", fd);
		}
		debug(VERSION_NOTSUPPORTED, "protocolo http no soportado", "not supported", fd);
		file = fopen(fich_version, "r");
		strcat(buff_respuesta, " 505 HTTP Version Not Supported\r\n");
		break;
	}
	//Fecha
	strftime(buff_fecha, sizeof(buff_fecha), "Date: %a, %e %b %Y %T %Z\r\n", now_tm);
	strcat(buff_respuesta, buff_fecha);
	//Server
	strcat(buff_respuesta, "Server: servidor_arturo\r\n");
	//Tamaño
	sprintf(tamano, "Content-Length: %ld\r\n", info_fichero.st_size);
	strcat(buff_respuesta, tamano);
	//Connection
	strcat(buff_respuesta, "Connection: Keep-Alive\r\n");
	//Keep Alive
	strcat(buff_respuesta, "Keep-Alive: timeout=60, max=100\r\n");
	//Tipo de fichero
	strcat(buff_respuesta, "Content-Type: ");
	strcat(buff_respuesta, extensions[extension].filetype);
	strcat(buff_respuesta, "\r\n");
	//Cierre de cabecera
	strcat(buff_respuesta, "\r\n");
	//Mandamos la cabecera de la respuesta
	int bytesRespuesta = write(fd, buff_respuesta, strlen(buff_respuesta));
	while (bytesRespuesta != strlen(buff_respuesta))
	{
		bytesRespuesta += write(fd, buff_respuesta + bytesRespuesta, strlen(buff_respuesta) - bytesRespuesta);
	}
	//Mandamos el archivo
	int bytesFichero = 0;
	memset(buff_respuesta, 0, BUFSIZE);
	while ((bytesFichero = fread(buff_respuesta, 1, BUFSIZE, file)) != 0)
	{
		if (bytesFichero < 0)
		{
			close(fd);
			debug(ERROR, "fallo de lectura al mandar un error", "fail read", fd);
		}
		write(fd, buff_respuesta, bytesFichero);
		memset(buff_respuesta, 0, BUFSIZE);
	}
	exit(3);
}
void mandar_respuesta(char *ruta, int descriptorFichero, int tipoMensaje, struct request peticion)
{
	char buff_fecha[256] = {0};
	char tamano[256] = {0};
	char cookie[256] = {0};
	char buff_respuesta[BUFSIZE] = {0};
	int bytesRespuesta = 0;
	time_t fecha = time(NULL);
	struct tm *now_tm;
	now_tm = gmtime(&fecha);
	struct stat info_fichero;
	//Comprobamos que exista el fichero
	if (stat(ruta, &info_fichero) < 0)
	{
		printf("fichero no encontrado\n");
		mandar_error(NOENCONTRADO, descriptorFichero, peticion);
	}
	//Comprobamos si es HTTP 1.1.
	if (strcmp(peticion.protocolo, "HTTP/1.1") != 0)
	{
		printf("Protocolo distinto de http 1.1 (NO SOPORTADO) \n");
		mandar_error(VERSION_NOTSUPPORTED, descriptorFichero, peticion);
	}
	if (tipoMensaje == GET)
	{
		//comprobamos que no intente acceder a estructura superior de ficheros
		if (strncmp(peticion.archivo, "../", 3) == 0)
		{
			mandar_error(PROHIBIDO, descriptorFichero, peticion);
		}
		//Como se trata el caso excepcional de la URL que no apunta a ningún fichero html
		if (S_ISDIR(info_fichero.st_mode))
		{
			strcat(ruta, "/index.html");
			if (stat(ruta, &info_fichero) < 0)
			{
				mandar_error(NOENCONTRADO, descriptorFichero, peticion);
			}
		}
	}
	//Miramos la extensión del fichero para saber si se soporta la extensión.
	char *extension = strrchr(ruta, '.'); //Nos devuelve la cadena a partir del último punto encontrado.
	extension = extension + 1;			  //Para quitarle el punto de la extensión.
	int tipoExt = -1;
	for (int i = 0; i < 10; i++)
	{
		if (strcmp(extension, extensions[i].ext) == 0)
		{
			tipoExt = i;
		}
	}
	if (tipoExt == -1)
	{
		mandar_error(NOACEPTABLE, descriptorFichero, peticion);
	}
	//Ahora que ya sabemos que nos están pidiendo un archivo válido pasamos a montar la respuesta HTTP
	if (access(ruta, R_OK) != -1)
	{
		FILE *file = fopen(ruta, "r");
		if (file != NULL)
		{
			//200 ok
			strcat(buff_respuesta, "HTTP/1.1 200 OK\r\n");
			//Fecha
			strftime(buff_fecha, sizeof(buff_fecha), "Date: %a, %e %b %Y %T %Z\r\n", now_tm);
			strcat(buff_respuesta, buff_fecha);
			//Server
			strcat(buff_respuesta, "Server: servidor_arturo\r\n");
			//Tamaño
			sprintf(tamano, "Content-Length: %ld\r\n", info_fichero.st_size);
			strcat(buff_respuesta, tamano);
			//Connection
			strcat(buff_respuesta, "Connection: Keep-Alive\r\n");
			//Keep Alive
			strcat(buff_respuesta, "Keep-Alive: timeout=60, max=100\r\n");
			//Tipo de fichero
			strcat(buff_respuesta, "Content-Type: ");
			strcat(buff_respuesta, extensions[tipoExt].filetype);
			strcat(buff_respuesta, "\r\n");
			//Cookie
			sprintf(cookie, "Set-Cookie: accesos=%d; max-age=120 \r\n", peticion.cookieContador);
			strcat(buff_respuesta, cookie);
			//Cierre de cabecera
			strcat(buff_respuesta, "\r\n");
			//Mandamos la cabecera de la respuesta
			bytesRespuesta = write(descriptorFichero, buff_respuesta, strlen(buff_respuesta));
			while (bytesRespuesta != strlen(buff_respuesta))
			{
				bytesRespuesta += write(descriptorFichero, buff_respuesta + bytesRespuesta, strlen(buff_respuesta) - bytesRespuesta);
			}
			//Mandamos el archivo
			int bytesFichero = 0;
			memset(buff_respuesta, 0, BUFSIZE);
			while ((bytesFichero = fread(buff_respuesta, 1, BUFSIZE, file)) != 0)
			{
				if (bytesFichero < 0)
				{
					close(descriptorFichero);
					debug(ERROR, "fallo de lectura al mandar un fichero", "fail read", descriptorFichero);
				}
				write(descriptorFichero, buff_respuesta, bytesFichero);
				memset(buff_respuesta, 0, BUFSIZE);
			}
			fclose(file);
		}
		else
			mandar_error(NOENCONTRADO, descriptorFichero, peticion);
	}
	else
		mandar_error(PROHIBIDO, descriptorFichero, peticion);
}
void process_web_request(int descriptorFichero)
{
	debug(LOG, "request", "Ha llegado una peticion", descriptorFichero);
	//
	// Definir buffer y variables necesarias para leer las peticiones
	//
	char buff_peticion[BUFSIZE] = {0};
	struct request peticion;
	peticion.tipo = "";
	peticion.archivo = "";
	peticion.protocolo = "";
	peticion.cookieContador = 0;
	//
	// Leer la petición HTTP
	ssize_t count = read(descriptorFichero, buff_peticion, BUFSIZE);

	// Comprobación de errores de lectura
	if (count < 0)
	{
		close(descriptorFichero);
		//TODO debug
		debug(ERROR, "lectura del socket erronea", "fail read", descriptorFichero);
		return;
	}
	//LEEMOS LA PRIMERA LINEA
	char *saveptr1;
	char *token_linea = strtok_r(buff_peticion, "\n", &saveptr1);
	parser_first_line(token_linea, &peticion);
	//SEGUIMOS CON EL RESTO DE LA PETICION
	token_linea = strtok_r(NULL, "\r\n", &saveptr1);
	char *aux_token;
	//Comprobamos que no sea una bad request
	if (peticion.tipo == NULL || peticion.archivo == NULL || peticion.protocolo == NULL)
	{
		mandar_error(BAD_REQUEST, descriptorFichero, peticion);
	}
	//Parsear el post
	if (strcmp(peticion.tipo, "POST") == 0)
	{
		while (token_linea != NULL)
		{
			token_linea = strtok_r(NULL, "\r\n", &saveptr1);
			if (token_linea != NULL)
			{
				aux_token = token_linea;
			}
		}
		char *email = strrchr(aux_token, '=');
		email = email + 1;
		char *ruta;
		if (strcmp(email, "arturo.lorenzoh%40um.es") == 0)
		{
			ruta = "./accion_form.html";
		}
		else
		{
			ruta = "./no_accion.html";
		}
		mandar_respuesta(ruta, descriptorFichero, POST, peticion);
	} //Parsear el get
	else if (strcmp(peticion.tipo, "GET") == 0)
	{
		int isHost = 0;
		while (token_linea != NULL)
		{
			printf("%s\n", token_linea);
			if (strncmp(token_linea, "Host: ", 6) == 0)
			{
				isHost = 1;
				printf("Cabecera host encontrada: %s\n", token_linea);
			}
			if (strncmp(token_linea, "Cookie: ", 8) == 0)
			{
				peticion.cookieContador = parser_cookie(token_linea);
				printf("peticion: %d\n", peticion.cookieContador);
			}
			token_linea = "";
			token_linea = strtok_r(NULL, "\r\n", &saveptr1);
		}
		//Cookie
		if (peticion.cookieContador + 1 > 9) //si supera el limite de accesos mandamos 429
		{
			mandar_error(BAD_REQUEST, descriptorFichero, peticion);
		}else 
			peticion.cookieContador += 1;
		if (!isHost)
		{
			mandar_error(BAD_REQUEST, descriptorFichero, peticion);
		}
		char ruta[PATH_MAX] = {0};
		strcat(ruta, ".");
		strcat(ruta, peticion.archivo);
		//Como se trata el caso de acceso ilegal a directorios superiores de la jerarquia de directorios del sistema
		mandar_respuesta(ruta, descriptorFichero, GET, peticion);
	}
	else
	{
		mandar_error(NOIMPLEMENTADO, descriptorFichero, peticion);
	}
}

int main(int argc, char **argv)
{
	int i, port, pid, listenfd, socketfd;
	socklen_t length;
	static struct sockaddr_in cli_addr;  // static = Inicializado con ceros
	static struct sockaddr_in serv_addr; // static = Inicializado con ceros

	//  Argumentos que se esperan:
	//
	//	argv[1]
	//	En el primer argumento del programa se espera el puerto en el que el servidor escuchara
	//
	//  argv[2]
	//  En el segundo argumento del programa se espera el directorio en el que se encuentran los ficheros del servidor
	//
	//  Verficiar que los argumentos que se pasan al iniciar el programa son los esperados
	//

	//
	//  Verficiar que el directorio escogido es apto. Que no es un directorio del sistema y que se tienen
	//  permisos para ser usado
	//

	if (chdir(argv[2]) == -1)
	{
		(void)printf("ERROR: No se puede cambiar de directorio %s\n", argv[2]);
		exit(4);
	}
	// Hacemos que el proceso sea un demonio sin hijos zombies
	if (fork() != 0)
		return 0; // El proceso padre devuelve un OK al shell

	(void)signal(SIGCHLD, SIG_IGN); // Ignoramos a los hijos
	(void)signal(SIGHUP, SIG_IGN);  // Ignoramos cuelgues

	debug(LOG, "web server starting...", argv[1], getpid());

	/* setup the network socket */
	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		debug(ERROR, "system call", "socket", 0);

	port = atoi(argv[1]);

	if (port < 0 || port > 60000)
		debug(ERROR, "Puerto invalido, prueba un puerto de 1 a 60000", argv[1], 0);

	/*Se crea una estructura para la información IP y puerto donde escucha el servidor*/
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); /*Escucha en cualquier IP disponible*/
	serv_addr.sin_port = htons(port);			   /*... en el puerto port especificado como parámetro*/

	if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		debug(ERROR, "system call", "bind", 0);

	if (listen(listenfd, 64) < 0)
		debug(ERROR, "system call", "listen", 0);
	while (1)
	{
		length = sizeof(cli_addr);
		if ((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)
			debug(ERROR, "system call", "accept", 0);
		if ((pid = fork()) < 0)
		{
			debug(ERROR, "system call", "fork", 0);
		}
		else
		{
			if (pid == 0)
			{ // Proceso hijo
				(void)close(listenfd);
				struct timeval timeout;
				fd_set rfds;
				timeout.tv_sec = 60;
				timeout.tv_usec = 0;
				FD_ZERO(&rfds);
				FD_SET(socketfd, &rfds);
				while (select(socketfd + 1, &rfds, NULL, NULL, &timeout))
				{
					process_web_request(socketfd); // El hijo termina tras llamar a esta función
					timeout.tv_sec = 60;
				}
				close(socketfd);
				exit(1);
			}
			else
			{ // Proceso padre
				(void)close(socketfd);
			}
		}
	}
}
