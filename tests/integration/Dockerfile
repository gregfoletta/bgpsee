FROM frrouting/frr:v8.4.1

# Copy FRR configuration files
COPY frr/daemons /etc/frr/daemons
COPY frr/frr.conf /etc/frr/frr.conf
COPY frr/vtysh.conf /etc/frr/vtysh.conf

# Set proper permissions
RUN chown -R frr:frr /etc/frr && chmod 640 /etc/frr/*

# Expose BGP port
EXPOSE 179

# Start FRR
CMD ["/usr/lib/frr/docker-start"]
