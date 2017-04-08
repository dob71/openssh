/* $OpenBSD: auth-options.h,v 1.21 2015/01/14 10:30:34 markus Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef AUTH_OPTIONS_H
#define AUTH_OPTIONS_H

/* Handling permitted -R exception ports to listen on */
/* The exceptions are allowed in per session config when -R is off globally. */
#define PORT_MAP_SIZE (65536 / 8) /* Aloowed listener ports bitmap size in bytes */
#define ADD_PERMITTED_PORT(_p) (permitted_listen[((_p) & 0xFFFF) >> 3] |= 1 << ((_p) & 0x7))
#define CLEAR_PERMITTED_PORT(_p) (permitted_listen[((_p) & 0xFFFF) >> 3] &= ~(1 << ((_p) & 0x7)))
#define IS_PERMITTED_PORT(_p) (permitted_listen[((_p) & 0xFFFF) >> 3] & (1 << ((_p) & 0x7)))
#define PERMITTED_PORTS_CLEAR_ALL() memset(permitted_listen, 0, sizeof(permitted_listen))
#define PERMITTED_PORTS_ADD_ALL() memset(permitted_listen, 0xFF, sizeof(permitted_listen))

extern unsigned char permitted_listen[];

/* Linked list of custom environment strings */
struct envstring {
	struct envstring *next;
	char   *s;
};

/* Flags that may be set in authorized_keys options. */
extern int no_port_forwarding_flag;
extern int no_agent_forwarding_flag;
extern int no_x11_forwarding_flag;
extern int no_pty_flag;
extern int no_user_rc;
extern char *forced_command;
extern struct envstring *custom_environment;
extern int forced_tun_device;
extern int key_is_cert_authority;
extern char *authorized_principals;

int	auth_parse_options(struct passwd *, char *, char *, u_long);
void	auth_clear_options(void);
int	auth_cert_options(struct sshkey *, struct passwd *);

#endif
