# Stands in for untrusted code. It tries the network and reports the result;
# under untrusted-python the connect must fail.
import socket

try:
    socket.create_connection(("127.0.0.1", 9), timeout=2).close()
    print("network: reachable (unexpected)")
except OSError as e:
    print(f"network: blocked ({e.__class__.__name__})")
