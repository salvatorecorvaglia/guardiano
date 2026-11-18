# Keep PostgreSQL 16 and the upstream entrypoint, replacing its privilege-drop helper.
FROM postgres:18-alpine@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015
# Upstream gosu embeds an obsolete Go runtime. Use Alpine's native C helper for
# the entrypoint's only privilege-drop invocation and remove both upstream aliases.
RUN apk add --no-cache su-exec 'krb5-libs>=1.22.3-r0' 'libxslt>=1.1.43-r4' \
    && test -x /sbin/su-exec \
    && rm /usr/local/bin/gosu /usr/local/bin/su-exec \
    && sed -i 's/exec gosu postgres /exec \/sbin\/su-exec postgres /' /usr/local/bin/docker-entrypoint.sh \
    && grep -q 'exec /sbin/su-exec postgres ' /usr/local/bin/docker-entrypoint.sh
