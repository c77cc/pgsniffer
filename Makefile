## from https://github.com/vincentbernat/hellogopher

MODULE   = $(shell env GO111MODULE=on $(GO) list -m)
PKGS     = $(or $(PKG),$(shell env GO111MODULE=on $(GO) list ./...))
VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || \
			cat $(CURDIR)/.version 2> /dev/null || echo v0)
TESTPKGS = $(shell env GO111MODULE=on $(GO) list -f \
			'{{ if or .TestGoFiles .XTestGoFiles }}{{ .ImportPath }}{{ end }}' \
			$(PKGS))
MAINPKGS = $(shell env GO111MODULE=on $(GO) list -f \
			'{{ if or .GoFiles }}{{ .ImportPath }}{{ end }}' \
			$(PKGS) |grep $(MODULE)/cmd)   ## The main-package must be in the cmd directory

BIN      = $(CURDIR)/bin

GO       = $(shell which go)
GOOS     = ""
GOARCH   = ""
TIMEOUT  = 15
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

export GO111MODULE=on
unexport http_proxy
unexport HTTPS_PROXY

.PHONY: all
all: fmt | $(BIN) ; $(info $(M) building executable…) @ ## Build program binary
	$Q for CURPKG in $(MAINPKGS); do \
		echo "building $$CURPKG to $(BIN)"; \
		GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o $(BIN)/$$(basename $$CURPKG) $$CURPKG; \
	done

.PHONY: win
win: fmt | $(BIN) ; $(info $(M) building executable…) @ ## Build program binary(windows only)
	$Q for CURPKG in $(MAINPKGS); do \
		echo "building $$CURPKG to $(BIN)"; \
		GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC="x86_64-w64-mingw32-gcc" $(GO) build -ldflags "-w -s" -o $(BIN)/$$(basename $$CURPKG).exe $$CURPKG; \
	done

# Tools

$(BIN):
	@mkdir -p $@
$(BIN)/%: | $(BIN) ; $(info $(M) building $(PACKAGE)…)
	$Q tmp=$$(mktemp -d); \
	   env GO111MODULE=off GOPATH=$$tmp GOBIN=$(BIN) $(GO) get $(PACKAGE) \
		|| ret=$$?; \
	   rm -rf $$tmp ; exit $$ret

GOLINT = $(BIN)/golint
$(BIN)/golint: PACKAGE=golang.org/x/lint/golint

GOMOCKERY = $(BIN)/mockery
$(BIN)/mockery: PACKAGE=github.com/vektra/mockery/cmd/mockery

# Tests

TEST_TARGETS := test-default test-bench test-short test-verbose test-race
.PHONY: $(TEST_TARGETS) test-xml check test tests
test-bench:   ARGS=-run=__absolutelynothing__ -bench=. ## Run benchmarks
test-short:   ARGS=-short        ## Run only short tests
test-verbose: ARGS=-v            ## Run tests in verbose mode with coverage reporting
test-race:    ARGS=-race         ## Run tests with race detector
$(TEST_TARGETS): NAME=$(MAKECMDGOALS:test-%=%)
$(TEST_TARGETS): test
check test tests: fmt; $(info $(M) running $(NAME:%=% )tests…) @ ## Run tests
	$Q $(GO) test -timeout $(TIMEOUT)s $(ARGS) $(TESTPKGS)

COVERAGE_MODE    = atomic
COVERAGE_PROFILE = $(COVERAGE_DIR)/profile.out
COVERAGE_HTML    = $(COVERAGE_DIR)/index.html
.PHONY: test-coverage
test-coverage: COVERAGE_DIR := $(CURDIR)/test_result/coverage.$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
test-coverage: fmt; $(info $(M) running coverage tests…) @ ## Run coverage tests
	$Q mkdir -p $(COVERAGE_DIR)
	$Q $(GO) test \
		-covermode=$(COVERAGE_MODE) \
		-coverprofile="$(COVERAGE_PROFILE)" $(TESTPKGS)
	$Q $(GO) tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_HTML)

.PHONY: lint
lint: | $(GOLINT) ; $(info $(M) running golint…) @ ## Run golint
	$Q $(GOLINT) -set_exit_status $(PKGS)

.PHONY: mockery
mockery: | $(GOMOCKERY) ; $(info $(M) running mockery…) @ ## Run mockery(generates mocks for pkg/ directory)
	$Q $(GOMOCKERY) -dir pkg/ -all -inpkg -case underscore

.PHONY: fmt
fmt: ; $(info $(M) running gofmt…) @ ## Run gofmt on all source files
	$Q $(GO) fmt $(PKGS)

# Misc

.PHONY: clean
clean: ; $(info $(M) cleaning…)	@ ## Cleanup everything
	@rm -rf $(BIN)
	@rm -rf test_result/tests.* test_result/coverage.*

.PHONY: version
version:
	@echo $(VERSION)

.PHONY: help
help:
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
