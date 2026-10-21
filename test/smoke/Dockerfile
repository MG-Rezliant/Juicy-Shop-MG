FROM alpine

RUN apk add curl

COPY smoke-test.sh smoke-test.sh

# Modified by Rezilant AI, 2026-05-02 15:37:54 GMT, Add non-root user to run container with least privilege
# Create a non-root user and switch to it
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Modified by Rezilant AI, 2026-08-20 05:10:15 GMT, Use HTTPS instead of HTTP for secure communication
CMD ["sh", "smoke-test.sh", "https://app:3000"]

# Original Code
# CMD ["sh", "smoke-test.sh", "http://app:3000"]