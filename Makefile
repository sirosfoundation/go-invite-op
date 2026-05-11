# go-invite-op

.PHONY: help build run test test-coverage lint fmt vet tidy tools clean docker-build docker-run build-web clean install-web

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build-web: install-web ## Build web assets (CSS/JS)
	@echo "Building web assets..."
	@pnpm build

build: build-web ## Build the server binary
	@echo "Building server..."
	@go build -o bin/server cmd/server/main.go

run: build ## Build and run the server
	@echo "Running server..."
	@./bin/server

test: ## Run tests
	@echo "Running tests..."
	@go test -v -race -cover ./...

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1

lint: ## Run golangci-lint
	@echo "Running linter..."
	@golangci-lint run

fmt: ## Format code with gofmt and goimports
	@echo "Formatting..."
	@gofmt -w .
	@goimports -w -local github.com/sirosfoundation/go-invite-op .

vet: ## Run go vet
	@echo "Running vet..."
	@go vet ./...

tidy: ## Tidy go.mod/go.sum
	@echo "Tidying modules..."
	@go mod tidy

tools: ## Install development tools
	@echo "Installing tools..."
	@go install github.com/golangci-lint-lint/golangci-lint@v2.10.0
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/ web/dist/
	@rm -f coverage.out coverage.html

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t go-invite-op:latest .

docker-run: docker-build ## Build and run Docker container
	@echo "Running Docker container..."
	@docker run -p 8080:8080 -p 8081:8081 --rm go-invite-op:latest

install-web: ## Install web dependencies
	@echo "Installing web dependencies..."
	@pnpm install --frozen-lockfile
