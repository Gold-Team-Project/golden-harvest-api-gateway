# 1단계: 빌드 스테이지 (JDK 21 사용)
FROM amazoncorretto:21-alpine AS builder
WORKDIR /build

# 설정 파일 복사 (빌드 캐시)
COPY gradlew .
COPY gradle gradle
COPY build.gradle settings.gradle ./

# 의존성 다운로드
RUN ./gradlew --no-daemon dependencies

# 전체 소스 복사 및 JAR 파일 생성
COPY src src
RUN ./gradlew --no-daemon bootJar -x test

# 실행 스테이지
FROM amazoncorretto:21-alpine
WORKDIR /app

# 빌드 스테이지에서 생성된 jar만 복사
COPY --from=builder /build/build/libs/*.jar app.jar
