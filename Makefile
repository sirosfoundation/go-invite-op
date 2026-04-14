# go-invite-op

.PHONY: help build run test clean docker-build docker-run

help: ## Show this help
@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the server binary
@echo "Building server..."
@go build -o bin/server cmd/server/main.go

run: build ## Build and run the server
@echo "Running server..."
@./bin/server

test: ## Run tests
@echo "Running tests..."
@go test -v -race -cover ./...

test-coverage: ## Run tests with coverage
@echo "Running tests with coverage..."
@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
@go tool cover -html=coverage.out -o coverage.html
@go tool cover -func=coverage.out | tail -1

lint: ## Run linter
@echo "Running linter..."
@golangci-lint run

clean: ## Clean build artifacts
@echo "Cleaning..."
@rm -rf bin/
@rm -f coverage.out coverage.html

docker-build: ## Build Docker image
@echo "Building Docker image..."
@docker build -t go-invite-op:latest .

docker-run: docker-build ## Build and run Docker container
@echo "Running Docker container..."
@docker run -p 8080:8080 -p 8081:8081 --rm go-invite-op:latest
