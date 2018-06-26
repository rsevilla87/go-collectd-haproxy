sudo podman run -t --rm -v $(pwd)/haproxy.config:/etc/haproxy.config:z --net host haproxy haproxy -f /etc/haproxy.config
