FROM openwifi-clients-api:granular-access-20261012-r2
COPY server.py /app/server.py
COPY test_server.py /app/test_server.py
COPY test_access_http.py /app/test_access_http.py
COPY test_mlo.py /app/test_mlo.py
RUN cd /app && python -B -m unittest -v test_server.py test_access_http.py test_mlo.py
