#!/usr/bin/sh

doas -u postgres /usr/lib/psql15/bin/pg_ctl start -D $PGDATA -l /var/lib/postgresql/logfile
