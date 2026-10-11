FROM openwifi-clients-api:mlo-signal-20261011-r2
COPY server.py /app/server.py
COPY test_server.py /app/test_server.py
COPY test_access_http.py /app/test_access_http.py
RUN cd /app && python -B -m unittest -v test_server.py test_access_http.py
