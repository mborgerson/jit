TARGET := jit

jit: main.c
	gcc -o $@ -Wall $^

.PHONY: clean
clean:
	rm -f jit
