LOCAL_WEB_CONTAINER_NAME=backend
LOCAL_DOCKER_OPTIONS= -f docker-compose.yml
LOCAL_CELERY_CONTAINER_NAME=celery_worker



up:
	docker compose  $(LOCAL_DOCKER_OPTIONS) up -d

down:
	docker compose $(LOCAL_DOCKER_OPTIONS) down

stop:
	docker compose $(LOCAL_DOCKER_OPTIONS) stop

server:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) python manage.py runserver 0:8000

collectstatic:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) python manage.py collectstatic --noinput

build:
	docker compose $(LOCAL_DOCKER_OPTIONS) build

rebuild:
	docker compose $(LOCAL_DOCKER_OPTIONS) build --force-recreate --no-deps

logs:
	docker logs -f $(LOCAL_WEB_CONTAINER_NAME)

test:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) python manage.py test

ssh:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) /bin/sh

shell:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) python manage.py shell

superuser:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) python manage.py createsuperuser

requirements:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) pip install -r requirements.txt

migrations:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) python manage.py makemigrations

migrate:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) python manage.py migrate

reset-db:
	docker exec -it $(LOCAL_WEB_CONTAINER_NAME) python manage.py reset_db

celery:
	docker exec -it $(LOCAL_CELERY_CONTAINER_NAME) celery -A e_academy worker --loglevel=info
