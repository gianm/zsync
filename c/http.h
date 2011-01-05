/*
 *   http.h - simple HTTP client for zsync
 *
 *   Copyright (C) 2004,2005,2009 Colin Phipps <cph@moria.org.uk>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the Artistic License v2 (see the accompanying 
 *   file COPYING for the full license terms), or, at your option, any later 
 *   version of the same license.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   COPYING file for details.
 */

#include "libzsync/zsync.h"


extern char *referer;

extern char *cacert;
extern int be_insecure;
extern int be_verbose;

FILE* http_get(const char *orig_url, char **track_referer, const char *tfname);

struct range_fetch;

struct range_fetch* range_fetch_start(const char* orig_url, struct zsync_receiver* zr);
void range_fetch_addranges(struct range_fetch* rf, off_t* ranges, int nranges);
int range_fetch_perform(struct range_fetch* rf);
off_t range_fetch_bytes_down(const struct range_fetch* rf);
void range_fetch_end(struct range_fetch* rf);

void add_auth(char* host, char* user, char* pass);

/* base64.c */
char* base64(const char*);

