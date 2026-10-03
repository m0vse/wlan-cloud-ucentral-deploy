FROM openwifi-clients-api:root-only-r1
COPY server.py /app/server.py
COPY test_server.py /app/test_server.py
RUN python -B /app/test_server.py
