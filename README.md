# Rate Limiting Service

## Description

### Problem Statement

Implement a rate limiting service that can be used to limit the number of requests a client can make to an API within a specific time window. The service should be able to handle a large number of clients and high request rates.

### Requirements

- The service should be able to limit the number of requests a client can make to an API within a specific time window.

- The service should be able to handle a large number of clients and high request rates.

- The service should be able to run in a containerized environment.

### Storage Backends

- In-Memory: `HashMap`

### API

- `/status`: Returns the number of requests remaining for the client within the time window.

- `/request`: Emulates a request to the API. Each request should decrement the number of requests remaining for the client within the time window. If the number of requests remaining is zero, the request should be rejected with 429, To Many Requests response. The response should include the number of seconds until the client can make another request. Respond with 200, OK if the request is accepted.
