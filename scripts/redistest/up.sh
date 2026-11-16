#!/bin/sh
# Starts two throwaway Redis servers on 127.0.0.1 for the tests of the Redis client, driver and tools, and prints the variables the tests
# read. One has no password and one wants the fixture's, which is fixed and public: these servers hold nothing and listen on the loopback
# only. Stop them with: docker rm -f securl-redis securl-redis-pw
#
# IMAGE can point at a mirror (docker.m.daocloud.io/library/redis:7-alpine) where Docker Hub cannot be reached.
set -eu
IMAGE="${IMAGE:-redis:7-alpine}"
PASSWORD="${SECURL_TEST_REDIS_PASSWORD:-T3st-Pass-9x}"
docker rm -f securl-redis securl-redis-pw >/dev/null 2>&1 || true
docker run -d --name securl-redis -p 127.0.0.1:36379:6379 "$IMAGE" >/dev/null
docker run -d --name securl-redis-pw -p 127.0.0.1:36380:6379 "$IMAGE" redis-server --requirepass "$PASSWORD" >/dev/null
i=0
until docker exec securl-redis redis-cli ping 2>/dev/null | grep -q PONG && docker exec securl-redis-pw redis-cli -a "$PASSWORD" --no-auth-warning ping 2>/dev/null | grep -q PONG; do
  i=$((i + 1)); [ "$i" -gt 30 ] && { echo "redis did not start" >&2; exit 1; }; sleep 1
done
echo "export SECURL_TEST_REDIS=127.0.0.1:36379 SECURL_TEST_REDIS_PW=127.0.0.1:36380 SECURL_TEST_REDIS_PASSWORD='$PASSWORD'"
