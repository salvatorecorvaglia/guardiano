FROM postgres:18-alpine@sha256:0115267ab5a509022df9319c77be365cef335adb71556c75f60f5360ee247e71
RUN apk add --no-cache su-exec 'krb5-libs>=1.22.3-r0' 'libxml2>=2.13.9-r3' 'libxslt>=1.1.43-r4' \
    && test -x /sbin/su-exec \
    && rm -f /usr/local/bin/gosu /usr/local/bin/su-exec \
    && sed -i 's/exec gosu postgres /exec \/sbin\/su-exec postgres /' /usr/local/bin/docker-entrypoint.sh \
    && grep -q 'exec /sbin/su-exec postgres ' /usr/local/bin/docker-entrypoint.sh
