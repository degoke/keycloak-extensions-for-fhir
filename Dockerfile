# ----------------------------------------------------------------------------
# (C) Copyright IBM Corp. 2021
#
# SPDX-License-Identifier: Apache-2.0
# ----------------------------------------------------------------------------

# Build stage
FROM maven:3-eclipse-temurin-17 AS build
COPY pom.xml ./
COPY keycloak-config ./keycloak-config
COPY keycloak-extensions ./keycloak-extensions

RUN mvn -B clean package -DskipTests


# Package stage
FROM quay.io/keycloak/keycloak:26.0.8

# Use H2 database for development (can be overridden)
ENV KC_DB=dev-file

# Copy the shaded JAR with all dependencies to the providers directory
COPY --from=build keycloak-extensions/target/keycloak-extensions-*-shaded.jar /opt/keycloak/providers/
