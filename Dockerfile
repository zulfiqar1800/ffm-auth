FROM python:3.8-slim-buster

RUN mkdir /app
WORKDIR /app
ENV SECRET_TEXT the_super_secret_text
RUN pip install setuptools

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt
EXPOSE 8000

COPY . /app

CMD ["python", "manage.py", "runserver"]
