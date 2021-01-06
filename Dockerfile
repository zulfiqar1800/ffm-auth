FROM python:3.8-slim-buster

RUN mkdir /app
WORKDIR /app
ENV SECRET_TEXT the_super_secret_text
RUN pip install setuptools

ENV WAIT_VERSION 2.7.2
ADD https://github.com/ufoscout/docker-compose-wait/releases/download/$WAIT_VERSION/wait /wait
RUN chmod +x /wait

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt
EXPOSE 8000

COPY . /app

CMD ["python", "manage.py", "runserver"]
