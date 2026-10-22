# Keep PostgreSQL 16 and the upstream entrypoint, replacing its privilege-drop helper.
FROM postgres:16-alpine@sha256:deb28ee471183cb0c303113dac9b2433c51eeeeb678def7af9a9ec5820367815
# Upstream gosu embeds an obsolete Go runtime. Use Alpine's native C helper for
# the entrypoint's only privilege-drop invocation and remove both upstream aliases.
RUN apk add --no-cache su-exec \
    && test -x /sbin/su-exec \
    && rm /usr/local/bin/gosu /usr/local/bin/su-exec \
    && sed -i 's/exec gosu postgres /exec \/sbin\/su-exec postgres /' /usr/local/bin/docker-entrypoint.sh \
    && grep -q 'exec /sbin/su-exec postgres ' /usr/local/bin/docker-entrypoint.sh
