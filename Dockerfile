FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN mkdir -p /app/data && chown -R nobody:nogroup /app/data
USER nobody
EXPOSE 3000
VOLUME ["/app/data"]
CMD ["python3", "server.py", "--host", "0.0.0.0", "--port", "3000"]
