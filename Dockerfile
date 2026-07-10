FROM eclipse-temurin:25-jdk@sha256:68868d04fa9cfd5f5c6abec0b5cef86d8de2bf9c62c37c7d3e4f0f80f5cfd7ff AS build
WORKDIR /build

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
# Best-effort cache warm — some plugins still resolve during package, so this doesn't guarantee a
# fully offline build; it just reduces what gets re-downloaded when only src/ changes.
RUN ./mvnw -B dependency:go-offline

COPY src/ src/
RUN ./mvnw -B -DskipTests package

FROM eclipse-temurin:25-jre@sha256:d0eb1b9018b3044da1b7346f39e945f71095749853d69a3aa16b8c99dad9bb45
WORKDIR /app

RUN useradd --system --create-home --shell /usr/sbin/nologin gskart \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/*.war app.war
RUN chown gskart:gskart app.war
USER gskart

EXPOSE 4011
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=30s \
    CMD curl -f http://localhost:4011/actuator/health || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.war"]
