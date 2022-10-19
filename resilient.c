/* Copyright (C) 2022 Mateus de Lima Oliveira */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <pthread.h>

#define TIMEOUT 2000

ssh_channel channel;

const char config_host = "ativarsoft.com.br";
const char config_user = "";
const char config_password[] = "";

static void shutdown()
{
}

/* Signal handler */
void signal_handler(int signum)
{
  printf("Shutting down SSH tunnel.\n");
  shutdown();
}

void setup_signal_handler()
{
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = &signal_handler;
  sigaction(SIGTERM, &action, NULL);
}

void *connection_thread(void *vargp)
{
  /* port to connect on the server behind NAT */
  channel = ssh_channel_accept_forward(session, TIMEOUT, &port);
  if (channel == NULL)
  {
    fprintf(stderr, "Error waiting for incoming connection: %s\n",
            ssh_get_error(session));
    //return SSH_ERROR;
  }
  for (;;)
  {
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    if (nbytes < 0)
    {
      fprintf(stderr, "Error reading incoming data: %s\n",
              ssh_get_error(session));
      ssh_channel_send_eof(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
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
    printf("Sent answer\n");
  }
  ssh_channel_send_eof(channel);
  ssh_channel_free(channel);
  //return SSH_OK;
}

int web_server(ssh_session session)
{
  int rc;
  char buffer[256];
  int nbytes, nwritten;
  int port = 0;
  pthread_t thread_id;
  ssh_session session;

  char *host = config_host;
  char *user = config_user;

  session = ssh_new();
  if (session == NULL)
    return 1;

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

  rc = ssh_userauth_password(my_ssh_session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS)
  {
    fprintf(stderr, "Error authenticating with password: %s\n",
      ssh_get_error(my_ssh_session));
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    return 1;
  }

  pthread_create();

  ssh_disconnect(session);
  ssh_free(session);

  return SSH_OK;
}
