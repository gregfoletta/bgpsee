FROM frrouting/frr:v8.4.1

# Copy FRR configuration files
COPY frr/daemons /etc/frr/daemons
COPY frr/frr.conf /etc/frr/frr.conf
COPY frr/vtysh.conf /etc/frr/vtysh.conf

# Set proper permissions
RUN chown -R frr:frr /etc/frr && chmod 640 /etc/frr/*

# Create startup script that sets up VRF and VXLAN interfaces before FRR starts
COPY start-frr.sh /usr/local/bin/start-frr.sh
RUN chmod +x /usr/local/bin/start-frr.sh

# Expose BGP port
EXPOSE 179

# Start with our custom script
CMD ["/usr/local/bin/start-frr.sh"]
