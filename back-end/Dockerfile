# First stage: build the application
FROM ubuntu:latest AS build

# Install required packages
RUN apt-get update && \
    apt-get install -y openjdk-17-jdk && \
    apt-get install -y wget unzip

# Set the working directory
WORKDIR /app

# Copy the entire project to the working directory
COPY . .

# Ensure the gradlew script has executable permissions
RUN chmod +x ./gradlew

# Build the application
RUN ./gradlew bootJar --no-daemon

# Second stage: create the final image
FROM openjdk:17-jdk-slim

# Expose the port the application will run on
EXPOSE 8080

# Copy the JAR file from the first stage
COPY --from=build /app/build/libs/website-0.0.1-SNAPSHOT.jar app.jar

# Set the entrypoint to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
