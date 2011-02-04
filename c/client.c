
/*
 *   zsync - client side rsync over http
 *   Copyright (C) 2004,2005,2007,2009 Colin Phipps <cph@moria.org.uk>
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

/* zsync command-line client program */

#include "zsglobal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#include "libzsync/zsync.h"

#include "http.h"
#include "url.h"
#include "progress.h"

/* For curl_global_init, curl_global_cleanup */
#include <curl/curl.h>

/* FILE* f = open_zcat_pipe(file_str)
 * Returns a (popen) filehandle which when read returns the un-gzipped content
 * of the given file. Or NULL on error; or the filehandle may fail to read. It
 * is up to the caller to call pclose() on the handle and check the return
 * value of that.
 */
FILE* open_zcat_pipe(const char* fname)
{
    /* Get buffer to build command line */
    char *cmd = malloc(6 + strlen(fname) * 2);
    if (!cmd)
        return NULL;

    strcpy(cmd, "zcat ");
    {   /* Add filename to commandline, escaping any characters that the shell
         *might consider special. */
        int i, j;

        for (i = 0, j = 5; fname[i]; i++) {
            if (!isalnum(fname[i]))
                cmd[j++] = '\\';
            cmd[j++] = fname[i];
        }
        cmd[j] = 0;
    }

    if (!no_progress)
        fprintf(stderr, "reading seed %s: ", cmd);
    {   /* Finally, open the subshell for reading, and return the handle */
        FILE* f = popen(cmd, "r");
        free(cmd);
        return f;
    }
}

/* read_seed_file(zsync, filename_str)
 * Reads the given file (decompressing it if appropriate) and applies the rsync
 * checksum algorithm to it, so any data that is contained in the target file
 * is written to the in-progress target. So use this function to supply local
 * source files which are believed to have data in common with the target.
 */
void read_seed_file(struct zsync_state *z, const char *fname) {
    /* If we should decompress this file */
    if (zsync_hint_decompress(z) && strlen(fname) > 3
        && !strcmp(fname + strlen(fname) - 3, ".gz")) {
        /* Open for reading */
        FILE *f = open_zcat_pipe(fname);
        if (!f) {
            perror("popen");
            fprintf(stderr, "not using seed file %s\n", fname);
        }
        else {

            /* Give the contents to libzsync to read and find any useful
             * content */
            zsync_submit_source_file(z, f, !no_progress);

            /* Close and check for errors */
            if (pclose(f) != 0) {
                perror("close");
            }
        }
    }
    else {
        /* Simple uncompressed file - open it */
        FILE *f = fopen(fname, "r");
        if (!f) {
            perror("open");
            fprintf(stderr, "not using seed file %s\n", fname);
        }
        else {

            /* Give the contents to libzsync to read, to find any content that
             * is part of the target file. */
            if (!no_progress)
                fprintf(stderr, "reading seed file %s: ", fname);
            zsync_submit_source_file(z, f, !no_progress);

            /* And close */
            if (fclose(f) != 0) {
                perror("close");
            }
        }
    }

    {   /* And print how far we've progressed towards the target file */
        long long done, total;

        zsync_progress(z, &done, &total);
        if (!no_progress)
            fprintf(stderr, "\rRead %s. Target %02.1f%% complete.      \n",
                    fname, (100.0f * done) / total);
    }
}

long long http_down;

/* A ptrlist is a very simple structure for storing lists of pointers. This is
 * the only function in its API. The structure (not actually a struct) consists
 * of a (pointer to a) void*[] and an int giving the number of entries.
 *
 * ptrlist = append_ptrlist(&entries, ptrlist, new_entry)
 * Like realloc(2), this returns the new location of the ptrlist array; the
 * number of entries is passed by reference and updated in place. The new entry
 * is appended to the list.
 */
static void **append_ptrlist(int *n, void **p, void *a) {
    if (!a)
        return p;
    p = realloc(p, (*n + 1) * sizeof *p);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    p[*n] = a;
    (*n)++;
    return p;
}

/* zs = read_zsync_control_file(location_str, filename)
 * Reads a zsync control file from either a URL or filename specified in
 * location_str. This is treated as a URL if no local file exists of that name
 * and it starts with a URL scheme ; only http URLs are supported.
 * Second parameter is a filename in which to locally save the content of the
 * .zsync _if it is retrieved from a URL_; can be NULL in which case no local
 * copy is made.
 */
struct zsync_state *read_zsync_control_file(const char *p, const char *fn) {
    FILE *f;
    struct zsync_state *zs;
    char *lastpath = NULL;

    /* Try opening as a local path */
    f = fopen(p, "r");
    if (!f) {
        /* No such local file - if not a URL either, report error */
        if (!is_url_absolute(p)) {
            perror(p);
            exit(2);
        }

        /* Try URL fetch */
        f = http_get(p, &lastpath, fn);
        if (!f) {
            fprintf(stderr, "could not read control file from URL %s\n", p);
            exit(3);
        }
        referer = lastpath;
    }

    /* Read the .zsync */
    if ((zs = zsync_begin(f)) == NULL) {
        exit(1);
    }

    /* And close it */
    if (fclose(f) != 0) {
        perror("fclose");
        exit(2);
    }
    return zs;
}

/* str = get_filename_prefix(path_str)
 * Returns a (malloced) string of the alphanumeric leading segment of the
 * filename in the given file path.
 */
static char *get_filename_prefix(const char *p) {
    char *s = strdup(p);
    char *t = strrchr(s, '/');
    char *u;

    if (t)
        *t++ = 0;
    else
        t = s;
    u = t;
    while (isalnum(*u)) {
        u++;
    }
    *u = 0;
    if (*t > 0)
        t = strdup(t);
    else
        t = NULL;
    free(s);
    return t;
}

/* filename_str = get_filename(zs, source_filename_str)
 * Returns a (malloced string with a) suitable filename for a zsync download,
 * using the given zsync state and source filename strings as hints. */
char *get_filename(const struct zsync_state *zs, const char *source_name) {
    char *p = zsync_filename(zs);
    char *filename = NULL;

    if (p) {
        if (strchr(p, '/')) {
            fprintf(stderr,
                    "Rejected filename specified in %s, contained path component.\n",
                    source_name);
            free(p);
        }
        else {
            char *t = get_filename_prefix(source_name);

            if (t && !memcmp(p, t, strlen(t)))
                filename = p;
            else
                free(p);

            if (t && !filename) {
                fprintf(stderr,
                        "Rejected filename specified in %s - prefix %s differed from filename %s.\n",
                        source_name, t, p);
            }
            free(t);
        }
    }
    if (!filename) {
        filename = get_filename_prefix(source_name);
        if (!filename)
            filename = strdup("zsync-download");
    }
    return filename;
}

/* prog = calc_zsync_progress(zs)
 * Returns the progress ratio 0..1 (none...done) for the given zsync_state */
static float calc_zsync_progress(const struct zsync_state *zs) {
    long long zgot, ztot;

    zsync_progress(zs, &zgot, &ztot);
    return (100.0f * zgot / ztot);
}

/* fetch_remaining_blocks_http(zs, url, type)
 * For the given zsync_state, using the given URL (which is a copy of the
 * actual content of the target file is type == 0, or a compressed copy of it
 * if type == 1), retrieve the parts of the target that are currently missing. 
 * Returns zero if this URL was useful, nonzero if we crashed and burned.
 */
int fetch_remaining_blocks_http(struct zsync_state *z, const char *url,
                                int type) {
    int ret = 0;
    struct range_fetch *rf;
    struct zsync_receiver *zr;

    /* URL might be relative - we need an absolute URL to do a fetch */
    char *u = make_url_absolute(referer, url);
    if (!u) {
        fprintf(stderr,
                "URL '%s' from the .zsync file is relative, but I don't know the referer URL (you probably downloaded the .zsync separately and gave it to me as a file). I need to know the referring URL (the URL of the .zsync) in order to locate the download. You can specify this with -u (or edit the URL line(s) in the .zsync file you have).\n",
                url);
        return -1;
    }

    /* Start a range fetch and a zsync receiver */
    zr = zsync_begin_receive(z, type);
    if (!zr) {
        free(u);
        return -1;
    }
    rf = range_fetch_start(u, zr);
    if (!rf) {
        zsync_end_receive(zr);
        free(u);
        return -1;
    }

    if (!no_progress)
        fprintf(stderr, "downloading from %s:", u);

    {   /* Get a set of byte ranges that we need to complete the target */
        int nrange;
        off_t *zbyterange = zsync_needed_byte_ranges(z, &nrange, type);
        if (!zbyterange)
            return 1;
        if (nrange == 0)
            return 0;

        /* And give that to the range fetcher */
        range_fetch_addranges(rf, zbyterange, nrange);
        free(zbyterange);
    }

    {
        struct progress p = { 0, 0, 0, 0 };

        /* Set up progress display to run during the fetch */
        if (!no_progress) {
            fputc('\n', stderr);
            do_progress(&p, calc_zsync_progress(z), range_fetch_bytes_down(rf));
        }

        do {
            ret = range_fetch_perform(rf);

            if (ret && ! no_progress) {
                /* Maintain progress display
                 * XXX: Non-curl version could update in the middle of responses */
                do_progress(&p, calc_zsync_progress(z),
                            range_fetch_bytes_down(rf));
            }
        } while( ret > 0 );

        if (!no_progress)
            end_progress(&p, zsync_status(z) >= 2 ? 2 : ret == 0 ? 1 : 0);
    }

    /* Clean up */
    http_down += range_fetch_bytes_down(rf);
    zsync_end_receive(zr);
    range_fetch_end(rf);
    free(u);
    return ret;
}

/* fetch_remaining_blocks(zs)
 * Using the URLs in the supplied zsync state, downloads data to complete the
 * target file. 
 */
int fetch_remaining_blocks(struct zsync_state *zs) {
    int n, utype;
    const char *const *url = zsync_get_urls(zs, &n, &utype);
    int *status;        /* keep status for each URL - 0 means no error */
    int ok_urls = n;

    if (!url) {
        fprintf(stderr, "no URLs available from zsync?");
        return 1;
    }
    status = calloc(n, sizeof *status);

    /* Keep going until we're done or have no useful URLs left */
    while (zsync_status(zs) < 2 && ok_urls) {
        /* Still need data; pick a URL to use. */
        int try = rand() % n;

        if (!status[try]) {
            const char *tryurl = url[try];

            /* Try fetching data from this URL */
            int rc = fetch_remaining_blocks_http(zs, tryurl, utype);
            if (rc != 0) {
                fprintf(stderr, "failed to retrieve from %s\n", tryurl);
                status[try] = 1;
                ok_urls--;
            }
        }
    }
    free(status);
    return 0;
}

static int set_mtime(char* filename, time_t mtime) {
    struct stat s;
    struct utimbuf u;

    /* Get the access time, which I don't want to modify. */
    if (stat(filename, &s) != 0) {
        perror("stat");
        return -1;
    }
    
    /* Set the modification time. */
    u.actime = s.st_atime;
    u.modtime = mtime;
    if (utime(filename, &u) != 0) {
        perror("utime");
        return -1;
    }
    return 0;
}

/****************************************************************************
 *
 * Main program */
int main(int argc, char **argv) {
    struct zsync_state *zs;
    char *temp_file = NULL;
    char **seedfiles = NULL;
    int nseedfiles = 0;
    char *filename = NULL;
    long long local_used;
    char *zfname = NULL;
    time_t mtime;

    srand(getpid());
    {   /* Option parsing */
        int opt;
        while ((opt = getopt(argc, argv, "A:k:o:i:Vsqvu:C:KT:")) != -1) {
            switch (opt) {
            case 'A':           /* Authentication options for remote server */
                {               /* Scan string as hostname=username:password */
                    char *p = strdup(optarg);
                    char *q = strchr(p, '=');
                    char *r = q ? strchr(q, ':') : NULL;

                    if (!q || !r) {
                        fprintf(stderr,
                                "-A takes hostname=username:password\n");
                        exit(1);
                    }
                    else {
                        /* XXX - HTTP Auth not working right now */
                        fprintf(stderr,
                               "HTTP Authentication is not supported in this version\n");
                        exit(1);

                        /*
                        *q++ = *r++ = 0;
                        add_auth(p, q, r);
                        */
                    }
                }
                break;
            case 'k':
                free(zfname);
                zfname = strdup(optarg);
                break;
            case 'o':
                free(filename);
                filename = strdup(optarg);
                break;
            case 'i':
                seedfiles = append_ptrlist(&nseedfiles, seedfiles, optarg);
                break;
            case 'V':
                printf(PACKAGE " v" VERSION " (compiled " __DATE__ " " __TIME__
                       ")\n" "By Colin Phipps <cph@moria.org.uk>\n"
                       "Published under the Artistic License v2, see the COPYING file for details.\n");
                exit(0);
            case 's':
            case 'q':
                no_progress = 1;
                break;
            case 'v':
                be_verbose = 1;
                break;
            case 'u':
                referer = strdup(optarg);
                break;
            case 'C':
                /* CA Cert path */
                cacert = strdup(optarg);
                break;
            case 'K':
                /* Insecure (disable SSL host/peer verification) */
                be_insecure = 1;
                break;
            case 'T':
                /* Timeout */
                {
                    char *endptr = NULL;
                    errno = 0;
                    use_timeout = strtol( optarg, &endptr, 10 );
                    if( errno || *endptr != 0 || use_timeout < 0 ) {
                        /* Unable to convert, garbage at the end of the string, or number was negative */
                        fprintf( stderr, "Timeout (-T): Invalid number `%s'\n", optarg );
                        exit(1);
                    }
                }
                break;
            }
        }
    }

    /* Last and only non-option parameter must be the path/URL of the .zsync */
    if (optind == argc) {
        fprintf(stderr,
                "No .zsync file specified.\nUsage: zsync http://example.com/some/filename.zsync\n");
        exit(3);
    }
    else if (optind < argc - 1) {
        fprintf(stderr,
                "Usage: zsync http://example.com/some/filename.zsync\n");
        exit(3);
    }

    /* No progress display except on terminal */
    if (!isatty(0))
        no_progress = 1;

    /* Respect ZSYNC_CA_BUNDLE environment variable */
    if( !cacert ) {
        char *env_cacert;
        if( env_cacert = getenv("ZSYNC_CA_BUNDLE") ) {
            cacert = strdup(env_cacert);
        }
    }

    /* Global libcurl init -- must be called exactly once per program */
    if( curl_global_init( CURL_GLOBAL_ALL ) ) {
        /* libcurl is busted */
        fprintf(stderr,
                "curl_global_init failed miserably!\n");
        exit(3);
    }

    /* STEP 1: Read the zsync control file */
    if ((zs = read_zsync_control_file(argv[optind], zfname)) == NULL)
        exit(1);

    /* Get eventual filename for output, and filename to write to while working */
    if (!filename)
        filename = get_filename(zs, argv[optind]);
    temp_file = malloc(strlen(filename) + 6);
    strcpy(temp_file, filename);
    strcat(temp_file, ".part");

    /* Bail out for 0 length files */
    if (! zsync_filelen(zs)) {
        FILE *f = fopen(filename, "w");
        if (!f) {
            perror("open");
            fprintf(stderr, "Could not open %s for writing zero byte file\n", filename);
            exit(1);
        }
        mtime = zsync_mtime(zs);
        if (mtime != -1) set_mtime(filename, mtime);
        return 0;
    }

    {   /* STEP 2: read available local data and fill in what we know in the
         *target file */
        int i;

        /* Try any seed files supplied by the command line */
        for (i = 0; i < nseedfiles; i++) {
            read_seed_file(zs, seedfiles[i]);
        }
        /* If the target file already exists, we're probably updating that file
         * - so it's a seed file */
        if (!access(filename, R_OK)) {
            read_seed_file(zs, filename);
        }
        /* If the .part file exists, it's probably an interrupted earlier
         * effort; a normal HTTP client would 'resume' from where it got to,
         * but zsync can't (because we don't know this data corresponds to the
         * current version on the remote) and doesn't need to, because we can
         * treat it like any other local source of data. Use it now. */
        if (!access(temp_file, R_OK)) {
            read_seed_file(zs, temp_file);
        }

        /* Show how far that got us */
        zsync_progress(zs, &local_used, NULL);

        /* People that don't understand zsync might use it wrongly and end up
         * downloading everything. Although not essential, let's hint to them
         * that they probably messed up. */
        if (!local_used) {
            if (!no_progress)
                fputs
                    ("No relevent local data found - I will be downloading the whole file. If that's not what you want, CTRL-C out. You should specify the local file is the old version of the file to download with -i (you might have to decompress it with gzip -d first). Or perhaps you just have no data that helps download the file\n",
                     stderr);
        }
    }

    /* libzsync has been writing to a randomely-named temp file so far -
     * because we didn't want to overwrite the .part from previous runs. Now
     * we've read any previous .part, we can replace it with our new
     * in-progress run (which should be a superset of the old .part - unless
     * the content changed, in which case it still contains anything relevant
     * from the old .part). */
    if (zsync_rename_file(zs, temp_file) != 0) {
        perror("rename");
        exit(1);
    }

    /* STEP 3: fetch remaining blocks via the URLs from the .zsync */
    if (fetch_remaining_blocks(zs) != 0) {
        fprintf(stderr,
                "failed to retrieve all remaining blocks - no valid download URLs remain. Incomplete transfer left in %s.\n(If this is the download filename with .part appended, zsync will automatically pick this up and reuse the data it has already done if you retry in this dir.)\n",
                temp_file);
        exit(3);
    }

    {   /* STEP 4: verify download */
        int r;

        if (!no_progress)
            printf("verifying download...");
        r = zsync_complete(zs);
        switch (r) {
        case -1:
            fprintf(stderr, "Aborting, download available in %s\n", temp_file);
            exit(2);
        case 0:
            if (!no_progress)
                printf("no recognised checksum found\n");
            break;
        case 1:
            if (!no_progress)
                printf("checksum matches OK\n");
            break;
        }
    }

    free(temp_file);

    /* Get any mtime that we is suggested to set for the file, and then shut
     * down the zsync_state as we are done on the file transfer. Getting the
     * current name of the file at the same time. */
    mtime = zsync_mtime(zs);
    temp_file = zsync_end(zs);

    /* STEP 5: Move completed .part file into place as the final target */
    if (filename) {
        char *oldfile_backup = malloc(strlen(filename) + 8);
        int ok = 1;

        strcpy(oldfile_backup, filename);
        strcat(oldfile_backup, ".zs-old");

        if (!access(filename, F_OK)) {
            /* backup of old file */
            unlink(oldfile_backup);     /* Don't care if this fails - the link below will catch any failure */
            if (link(filename, oldfile_backup) != 0) {
                perror("link");
                fprintf(stderr,
                        "Unable to back up old file %s - completed download left in %s\n",
                        filename, temp_file);
                ok = 0;         /* Prevent overwrite of old file below */
            }
        }
        if (ok) {
            /* Rename the file to the desired name */
            if (rename(temp_file, filename) == 0) {
                /* final, final thing - set the mtime on the file if we have one */
                if (mtime != -1) set_mtime(filename, mtime);
            }
            else {
                perror("rename");
                fprintf(stderr,
                        "Unable to back up old file %s - completed download left in %s\n",
                        filename, temp_file);
            }
        }
        free(oldfile_backup);
        free(filename);
    }
    else {
        printf
            ("No filename specified for download - completed download left in %s\n",
             temp_file);
    }

    /* Final stats and cleanup */
    if (!no_progress)
        printf("used %lld local, fetched %lld\n", local_used, http_down);
    free(cacert);
    free(referer);
    free(temp_file);
    curl_global_cleanup();
    return 0;
}
