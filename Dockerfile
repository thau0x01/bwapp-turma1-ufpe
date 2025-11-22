FROM php:7.4-apache-bullseye

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping dnsutils \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install mysqli pdo pdo_mysql
RUN a2enmod rewrite

COPY ./bWAPP /var/www/html/
RUN chown -R www-data:www-data /var/www/html \
    && chmod 777 /var/www/html/passwords/ \
    && chmod 777 /var/www/html/images/ \
    && chmod 777 /var/www/html/documents/ \
    && chmod 777 /var/www/html/logs/

EXPOSE 80