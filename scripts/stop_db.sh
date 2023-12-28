#!/usr/bin/sh

doas -u postgres /usr/lib/psql15/bin/pg_ctl stop -D $PGDATA
