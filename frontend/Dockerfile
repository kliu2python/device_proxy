FROM nginx:1.25-alpine

RUN rm -rf /usr/share/nginx/html/* \
    && mkdir -p /usr/share/nginx/html/static

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY app.js /usr/share/nginx/html/static/app.js
COPY styles.css /usr/share/nginx/html/static/styles.css

EXPOSE 80
