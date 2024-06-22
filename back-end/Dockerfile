
# Sử dụng image Gradle để build
FROM gradle:7.4.2-jdk17 AS build
COPY . .

# Kiểm tra version của Gradle và Java để đảm bảo môi trường đúng
RUN gradle -v
RUN java -version

# Sử dụng cache cho Gradle
RUN gradle clean build -x test

# Sử dụng image OpenJDK cho runtime
FROM openjdk:17.0.1-jdk-slim

# Copy file jar từ bước build trước
COPY --from=build /app/build/libs/demo-0.0.1-SNAPSHOT.jar demo.jar

# Expose cổng 8080
EXPOSE 8080

# Chạy ứng dụng
ENTRYPOINT ["java", "-jar", "demo.jar"]