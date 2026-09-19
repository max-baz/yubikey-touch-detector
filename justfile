default: release

app := "yubikey-touch-detector"
version := `git describe --tags`

release: clean vendor
    mkdir -p dist

    git -c tar.tar.gz.command="gzip -cn" archive -o "dist/{{app}}-{{version}}.tar.gz" --format tar.gz --prefix "{{app}}-{{version}}/" "{{version}}"

    git -c tar.tar.gz.command="gzip -cn" archive -o "dist/{{app}}-{{version}}-vendored.tar.gz" --format tar.gz \
        `find vendor -type f -printf '--prefix={{app}}-{{version}}/%h/ --add-file=%p '` \
        --prefix "{{app}}-{{version}}/" "{{version}}"

    for file in dist/*; do \
        gpg --detach-sign --armor "$file"; \
    done

    rm -f "dist/{{app}}-{{version}}.tar.gz"

run *args:
    go run main.go {{args}}

build:
    # if you are building from git-archive tarballs, no need to pass -ldflags, the version is already hardcoded in main.go
    go build -ldflags "-X main.version={{version}}" -o {{app}} .
    scdoc < '{{app}}.1.scd' > '{{app}}.1'

lint:
    test -z "$(gofmt -l $(git ls-files '*.go'))"
    go vet ./...

test:
    go test ./...

vendor:
    go mod tidy
    go mod vendor

clean:
    rm -f {{app}}
    rm -f {{app}}.1
    rm -rf dist
    rm -rf vendor
