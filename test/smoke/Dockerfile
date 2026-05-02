FROM alpine

RUN apk add curl

COPY smoke-test.sh smoke-test.sh

# Modified by Rezilant AI, 2026-05-02 15:37:54 GMT, Add non-root user to run container with least privilege
# Create a non-root user and switch to it
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Original Code
# CMD ["sh", "smoke-test.sh", "http://app:3000"]
CMD ["sh", "smoke-test.sh", "http://app:3000"]