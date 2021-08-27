FROM alpine:3.7
RUN apk add --no-cache openjdk8-jre
COPY target/spring-security-hybrid-usage.jar /app.jar
ENTRYPOINT ["java",  "-jar", "/app.jar"]
EXPOSE 8080

