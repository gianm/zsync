/*
 *   zsync - client side rsync over http
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

extern const char http_scheme[];

char* __attribute__((pure)) make_url_absolute(const char* base, const char* url);

int __attribute__((pure)) is_url_absolute(const char* url);
