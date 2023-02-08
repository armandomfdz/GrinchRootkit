OPTS=-Wall -fPIC -shared -ldl

all: compile
	chmod 4755 grinch.so

compile:
	gcc -o grinch.so grinch.c ${OPTS}

clean:
	rm grinch.so
