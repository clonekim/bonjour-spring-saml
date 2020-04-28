FROM openjdk:8-jre-alpine
RUN apk upgrade musl
RUN apk del linux-pam
RUN apk --no-cache add tzdata && cp /usr/share/zoneinfo/Asia/Seoul /etc/localtime &&  echo "Asia/Seoul" > /etc/timezone
ENV LANG ko_KR.UTF-8
COPY backend*.jar                 /jars/backend.jar
COPY application.yml              /jars/application.yml
COPY keystore.jks                 /jars/keystore.jks
EXPOSE 8080
CMD ["java", "-jar", "/jars/backend.jar", "--spring.config.location=file:/jars/application.yml", "--sso.keystore.file=file:/jars/keystore.jks"]