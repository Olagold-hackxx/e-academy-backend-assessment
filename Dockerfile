FROM python:3.10.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Acceptable environment variables
ARG ALLOWED_HOSTS
ENV ALLOWED_HOSTS=$ALLOWED_HOSTS

ARG MYSQL_HOST
ENV MYSQL_HOST=$MYSQL_HOST

# Set work directory
WORKDIR /e_academy_backend

# Copy project
COPY . /e_academy_backend


# Install all dependencies
RUN apt-get update -y \
 && apt-get install -y  build-essential default-libmysqlclient-dev pkg-config python3-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --upgrade pip \
 && pip install -r requirements.txt \
 && chmod +x entrypoint.sh

CMD ["sh", "entrypoint.sh"]
