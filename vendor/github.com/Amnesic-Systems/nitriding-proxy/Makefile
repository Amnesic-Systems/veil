prog = nitriding-proxy
deps = cmd/*.go *.go go.mod go.sum Makefile

all: run

$(prog): $(deps)
	go build -C cmd/ -o ../$(prog)

.PHONY: cap
cap: $(prog)
	sudo setcap cap_net_admin=ep $(prog)

.PHONY: run
run: cap
	./$(prog)

.PHONY: clean
clean:
	rm -f $(prog)
