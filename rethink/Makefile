N ?= 5

SHARDS = $(shell seq 1 $(N))
COMPOSE_FILES = $(foreach i,$(SHARDS),-f rethink_shards/shard_${i}_compose.yml)

generate:
	@./generate_shards.sh $(N)

up: generate
	docker compose $(COMPOSE_FILES) up -d

down:
	docker compose $(COMPOSE_FILES) down -v

logs:
	docker compose $(COMPOSE_FILES) logs -f --tail=100

ps:
	docker compose $(COMPOSE_FILES) ps
