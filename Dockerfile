FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8-slim
WORKDIR /app
COPY . /app
RUN apt-get update && apt-get install -y  gcc python3-dev wkhtmltopdf xvfb

ENV XDG_RUNTIME_DIR=/app
ENV RUNLEVEL=3
#RUN source .bashrc
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
