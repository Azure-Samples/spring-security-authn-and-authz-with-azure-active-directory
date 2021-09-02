# Project Name

A project that demonstrates configuring Spring Security for AAD-specific features like On-Behalf-Of flow and AppRoles. It uses AAD's Boot starter to simplify configuration.

## Features

This project provides the following features:

* An OAuth 2.0 Client and two OAuth 2.0 Resource Servers. The client talks to the first resource server, which subsequently talks to the second resource server
* It uses the AAD Boot starter to simplify configuration

## Getting Started

### Prerequisites

- Requires JDK 8 or higher

### Quickstart

1. `git clone git@github.com:Azure-Samples/spring-security-authn-and-authz-with-azure-active-directory.git`
2. `cd spring-security-authn-and-authz-with-azure-active-directory`

## Demo

A demo app is included to show how to use the project.

To run the demo, follow these steps:

1. `./gradlew :facility-request:bootRun`
2. `./gradlew :facility-inventory:bootRun`
3. `./gradlew :hr:bootRun`
4. Navigate to http://localhost:8880

With the application started, you can click the "Login" button and log in as:

* user1@springonedemo20210830.onmicrosoft.com
* Voxu8138E

Then, you can click "Back" and then the "Request Standing Desk" button, and it should succeed.

Next, click "Back" again and then you can click the "Login" button and log in as:

* user2@springonedemo20210830.onmicrosoft.com
* Qava8536G

Then, you can click "Back" one more time and then the "Request Standing Desk" button, and it should fail.

## Resources

- [AAD Spring Boot Starter](https://github.com/Azure/azure-sdk-for-java/tree/main/sdk/spring/azure-spring-boot-starter-active-directory)
- [AAD Spring Boot Starter Reference Guide](https://docs.microsoft.com/en-us/azure/developer/java/spring-framework/spring-boot-starter-for-azure-active-directory-developer-guide)
- [Spring Security OAuth 2.0 Samples](https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/oauth2)
- [Spring Security OAuth 2.0 Reference](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2)
