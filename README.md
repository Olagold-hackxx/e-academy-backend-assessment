# E-Academy Backend

This backend service supports account creation (signup), authentication (login), password reset, email verification, and OTP-based verification for the E-Academy platform. Built with Django and Django Rest Framework (DRF), it also leverages Celery for scalable email handling and provides API documentation through Swagger.

## Table of Contents

- [Features](#features)
- [Project Setup](#project-setup)
  - [Environment Variables](#environment-variables)
  - [Running the Project](#running-the-project)
    - [Running Locally](#running-locally)
    - [Running with Docker](#running-with-docker)
- [API Documentation](#api-documentation)
- [Makefile Commands](#makefile-commands)

## Features

- **User Authentication**: Secure signup, login, and logout endpoints using JWT for token-based authentication.
- **Email Verification**: OTP-based email verification to confirm user accounts.
- **Password Management**: Request password reset and set a new password securely.
- **Scalable Email Handling**: Celery is used to handle email verification and password reset emails, allowing for better scalability and efficiency.
- **API Documentation**: Interactive API documentation with Swagger and Redoc, accessible at `/api/swagger` and `/api/doc`.

## Project Setup

### Environment Variables

The project relies on several environment variables for configuration. Set these up in a `.env` file:

| Variable               | Description                                       | Sample Value                     |
|------------------------|---------------------------------------------------|----------------------------------|
| `SECRET_KEY`           | Django secret key                                 | `<your_django_secret_key>`       |
| `FERNET_KEY`           | Key for encrypting sensitive data                 | Generated by `get_fernet_key.py` |
| `CELERY_BROKER_URL`    | URL for Celery message broker                     | `redis://localhost:6379/0`       |
| `CELERY_RESULT_BACKEND`| Backend for storing Celery task results           | `redis://localhost:6379/0`       |
| `EMAIL_HOST`           | SMTP host for sending emails                      | `smtp.mailtrap.io`               |
| `EMAIL_HOST_USER`      | SMTP username                                     | `<your_mailtrap_username>`       |
| `EMAIL_HOST_PASSWORD`  | SMTP password                                     | `<your_mailtrap_password>`       |
| `DEFAULT_FROM_EMAIL`   | Default email address for outgoing emails         | `no-reply@e-academy.com`         |

- **Secret Key**: Used by Django to secure sessions and tokens.
- **Fernet Key**: Generated by running `get_fernet_key.py` in the base folder.
- **Email Setup**: Use Mailtrap for development email testing, or configure your SMTP settings.
- **Celery Configuration**: If running locally, use `redis://localhost:6379/0` as the broker and result backend URL. For Docker, use `redis://redis:6379/0`.

### Running the Project

#### Prerequisites

- **Docker** (for Docker-based setup)
- **Make**: Ensure Make is installed to run the Makefile commands.

#### Running Locally

1. **Set up environment**:
   - Create a `.env` file in the project root and populate it with the required variables.
2. **Start Redis locally** (if not using Docker).
3. **Install Requirements**: 
```bash
pip install requirements.txt
```
4. **Start the Django server and Celery worker**:
   - Run `start_server.sh` to start the Django development server.
   - Run `start_worker.sh` to start the Celery worker.

#### Running with Docker

1. **Build and Start Containers**:
   ```bash
   make up
   ```
2. **Stopping Containers**:
   ```bash
   make down
   ```

### Makefile Commands

The Makefile provides a convenient way to manage Docker containers and common development tasks. Below are the available commands:

- **up**: Start the Docker containers in detached mode.
- **down**: Stop and remove the Docker containers.
- **stop**: Stop the running containers without removing them.
- **server**: Run Django’s development server inside the Docker container.
- **collectstatic**: Collect static files.
- **build**: Build the Docker images.
- **rebuild**: Force-recreate the Docker containers without dependencies.
- **logs**: Follow logs for the main container.
- **test**: Run tests inside the Docker container.
- **ssh**: Open an interactive shell in the main web container.
- **shell**: Open Django’s shell in the container.
- **superuser**: Create a superuser for the Django admin.
- **requirements**: Install requirements in the container.
- **migrations**: Generate new database migrations.
- **migrate**: Apply migrations to the database.
- **reset-db**: Reset the database to a clean state.
- **celery**: Start a Celery worker in the Celery container.

## API Documentation

The following API endpoints are available under `/api/auth`:

| Endpoint                | Description                                 |
|-------------------------|---------------------------------------------|
| `/login`                | Login for existing users                    |
| `/logout`               | Logout the current user                     |
| `/request_password_reset` | Request a password reset email          |
| `/resend_verification_otp` | Resend the OTP for email verification  |
| `/change_password`      | Set a new password                          |
| `/register`             | Register a new user                         |
| `/verify_email`         | Verify user email with an OTP               |

### Accessing API Documentation

- **Swagger**: Available at `/api/swagger` for interactive documentation.
- **Redoc**: Available at `/api/doc` for an alternative documentation view.
- **OpenAPI Schema**: Available at `/api/schema` for JSON-based schema documentation.

## Logging

The application has two log files:
- **info.log**: Logs general information and successful operations.
- **error.log**: Logs errors and issues encountered in the application, useful for debugging.

--- 
