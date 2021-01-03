FROM python:3.7

RUN mkdir /app
COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt
ENV SECRET_TEXT the_super_secret_text
EXPOSE 8000

CMD ["python", "manage.py", "runserver"]

