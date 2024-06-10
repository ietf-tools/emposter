FROM python:3.12-alpine
LABEL maintainer="IETF Tools Team <tools-discuss@ietf.org>"

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "server.py" ]
