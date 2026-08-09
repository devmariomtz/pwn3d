# ============================================================
# WARNING: This Dockerfile is INTENTIONALLY INSECURE.
# It contains multiple security anti-patterns for educational use.
# DO NOT use in production.
# ============================================================

# SECURITY ISSUE: Using EOL (End-of-Life) base image
# PHP 7.4 reached EOL on 2022-11-28. No security patches.
FROM php:7.4-apache

# SECURITY ISSUE: Hardcoded secrets in Dockerfile
ENV DB_PASSWORD=admin123
ENV API_SECRET=sk-1234567890abcdef
ENV APP_ENV=production
ENV APP_DEBUG=true

# SECURITY ISSUE: Running apt-get without cleanup, no --no-install-recommends
RUN apt-get update && apt-get install -y \
    libsqlite3-dev \
    wget \
    curl \
    unzip \
    git \
    vim \
    netcat \
    && docker-php-ext-install pdo pdo_sqlite

# SECURITY ISSUE: No WORKDIR set - files end up in /

# SECURITY ISSUE: Using ADD instead of COPY (ADD can fetch remote URLs and auto-extract tar)
ADD . /var/www/html/

# SECURITY ISSUE: World-writable permissions on everything
RUN chmod -R 777 /var/www/html/

# SECURITY ISSUE: Apache running as root, no user switch
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# SECURITY ISSUE: Enabling .htaccess overrides everywhere (can be exploited)
RUN sed -i 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf

# SECURITY ISSUE: Enabling directory listing
RUN sed -i 's/Options Indexes FollowSymLinks/Options +Indexes +FollowSymLinks/g' /etc/apache2/apache2.conf

# SECURITY ISSUE: No HEALTHCHECK defined
# SECURITY ISSUE: No USER directive (runs as root)
# SECURITY ISSUE: No dockerignore - .git, secrets, etc copied into image

# SECURITY ISSUE: Exposing port without any restrictions
EXPOSE 80

# SECURITY ISSUE: Running as root, no capability drop, no read-only filesystem
CMD ["apache2-foreground"]
