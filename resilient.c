/* Copyright (C) 2022 Mateus de Lima Oliveira */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include "resilient.h"

#define BUFFER_SIZE 128

typedef struct connection_thread_context {
	ssh_channel channel;
} conn_t, *conn_ptr_t;

typedef struct {
	pthread_t *ptr;
	size_t length;
} thread_array_t;

extern FILE *yyin;

int term = 0;
ssh_session session = NULL;
thread_array_t threads;

const char *config_host = NULL;
const char *config_user = NULL;
const char *config_password = NULL;
int config_timeout = 0;
int config_max_connections = 100;

int create_thread_array(size_t num_threads, thread_array_t *arr)
{
	pthread_t *threads = NULL;
	memset(arr, 0, sizeof(*arr));
	threads = calloc(num_threads, sizeof(*threads));
	if (threads == NULL)
		return 1;
	arr->ptr = threads;
	arr->length = num_threads;
	return 0;
}

void destroy_thread_array(thread_array_t *arr)
{
	pthread_t *threads = NULL;
	size_t size = 0;
	size_t length = 0;
	threads = arr->ptr;
	length = arr->length;
	size = length * sizeof(pthread_t);
	if (threads) {
		memset(threads, 0, size);
		free(threads);
	}
	arr->length = 0;
}

int create_connection_thread_context(conn_ptr_t *p)
{
	conn_ptr_t conn = NULL;
	p = NULL;
	conn = (conn_ptr_t) calloc(1, sizeof(conn_t));
	if (conn == NULL)
		return 1;
	*p = conn;
	return 0;
}

void destroy_connection_thread_context(conn_ptr_t p)
{
	if (p) {
		memset(p, 0, sizeof(conn_t));
		free(p);
	}
}

FILE *open_config_file()
{
	FILE *file = NULL;
	file = fopen("resilient.conf", "r");
	if (file != NULL)
		return file;
	file = fopen("/etc/resilient.conf", "r" );
	if (file != NULL)
		return file;
	return NULL;
}

void close_config_file(FILE *file)
{
	fclose(file);
}

int set_config_option_string(const char *name, const char *value)
{
	if (strcasecmp(name, "host") == 0) {
		config_host = strdup(value);
	} else if (strcasecmp(name, "user") == 0) {
		config_user = strdup(value);
	} else if (strcasecmp(name, "password") == 0) {
		config_password = strdup(value);
	} else {
		fprintf(stderr, "warning: unknown string configururation option: %s\n", name);
	}
	return 0;
}

int set_config_option_int(const char *name, int value)
{
	if (strcasecmp(name, "timeout") == 0) {
		if (value < 0) {
			fprintf(stderr, "error: invalid timout value\n");
			return 1;
		}
		config_timeout = value;
	} else if (strcasecmp(name, "max_connections") == 0) {
		if (value < 0) {
			fprintf(stderr, "error: invalid number of maximum connections\n");
			return 1;
		}
		config_max_connections = value;
	} else {
		fprintf(stderr, "warning: unknown integer configururation option: %s\n", name);
	}
	return 0;
}

static void shutdown_tunnel()
{
	term = 1;
}

/* Signal handler */
static void signal_handler(int signum)
{
  printf("Shutting down SSH tunnel.\n");
  switch (signum) {
    case SIGTERM:
    shutdown_tunnel();
    break;

    default:
    fprintf(stderr, "warning: unknown signal %d\n", signum);
    break;
  }
}

static void setup_signal_handler()
{
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = &signal_handler;
  sigaction(SIGTERM, &action, NULL);
}

void *connection_thread(void *vargp)
{
  char buffer[BUFFER_SIZE] = {};
  int nbytes = 0;
  conn_ptr_t conn = (conn_ptr_t) vargp;
  ssh_channel channel = conn->channel;
  int i = 0;

  for (;;)
  {
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    if (nbytes < 0)
    {
      fprintf(stderr, "Error reading incoming data: %s\n",
              ssh_get_error(session));
      ssh_channel_send_eof(channel);
      ssh_channel_free(channel);
      //return SSH_ERROR;
      return NULL;
    }
    //if (strncmp(buffer, "GET /", 5)) continue;

    /*nbytes = strlen(helloworld);
    nwritten = ssh_channel_write(channel, helloworld, nbytes);
    if (nwritten != nbytes)
    {
      fprintf(stderr, "Error sending answer: %s\n",
              ssh_get_error(session));
      ssh_channel_send_eof(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }*/
  }
  ssh_channel_send_eof(channel);
  ssh_channel_free(channel);
  destroy_connection_thread_context(conn);
  for (i = 0; i < config_max_connections; i++) {
	  if(threads.ptr[i] == pthread_self())
	    threads.ptr[i] = 0;
  }
  //return SSH_OK;
  return NULL;
}

int main()
{
  int rc;
  int port = 0;
  pthread_t thread_id = 0;
  FILE *config_file = NULL;
  conn_ptr_t conn = NULL;
  ssh_channel channel = 0;

  const char *host = NULL;
  const char *user = NULL;
  const char *password = NULL;
  int timeout = 0;
  int max_connections = 0;

  int verbosity = 0;

  size_t i = 0;
  
  config_file = open_config_file();
  if (config_file == NULL) {
    fprintf(stderr, "error: no configuration file found\n");
    return 1;
  }
  yyin = config_file;
  read_config_file();
  
  host = config_host;
  user = config_user;
  password = config_password;
  timeout = config_timeout;
  max_connections = config_max_connections;
  
  setup_signal_handler();
  
  rc = create_thread_array(max_connections, &threads);
  if (rc)
    return 1;

  session = ssh_new();
  if (session == NULL) {
    destroy_thread_array(&threads);
    return 1;
  }

  ssh_options_set(session, SSH_OPTIONS_HOST, host);
  ssh_options_set(session, SSH_OPTIONS_USER, user);
  ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
  ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, "aes128-ctr,aes256-ctr,3des-cbc");

  rc = ssh_connect(session);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error connecting: %s\n", ssh_get_error(session));
    ssh_free(session);
    return 1;
  }

  /* open port on the remote server (the server
   * with static IP. */
  /* Apache will connect to this port with
   * mod_proxy. */
  rc = ssh_channel_listen_forward(session, NULL, 12004, NULL);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error opening remote port: %s\n",
            ssh_get_error(session));
    return rc;
  }

  rc = ssh_userauth_password(session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS)
  {
    fprintf(stderr, "Error authenticating with password: %s\n",
      ssh_get_error(session));
    ssh_disconnect(session);
    ssh_free(session);
    return 1;
  }

  while (!term) {
    /* port to connect on the server behind NAT */
    channel = ssh_channel_accept_forward(session, timeout, &port);
    if (channel == NULL)
    {
      fprintf(stderr, "Error waiting for incoming connection: %s\n",
              ssh_get_error(session));
      //return SSH_ERROR;
    }
    rc = create_connection_thread_context(&conn);
    if (rc){
		fprintf(stderr, "error: not enough memory\n");
		break;
	}
	for (i = 0; i < threads.length && threads.ptr[i]; i++);
	if (i >= threads.length) {
		/* drop connection */
		continue;
	}
    pthread_create(&thread_id, NULL, &connection_thread, NULL);
    threads.ptr[i] = thread_id;
    //pthread_detach(thread_id);
  }
  for (i = 0; i < threads.length; i++) {
    if ((thread_id = threads.ptr[i])) {
      pthread_join(thread_id, NULL);
    }
  }

  ssh_disconnect(session);
  ssh_free(session);

  destroy_thread_array(&threads);

  return SSH_OK;
}
