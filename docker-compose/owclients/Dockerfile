FROM openwifi-clients-api:root-only-r1
COPY server.py /app/server.py
COPY test_server.py test_access_http.py test_mlo.py test_details.py /app/
RUN python -B -m unittest -v test_server.py test_access_http.py test_mlo.py test_details.py
