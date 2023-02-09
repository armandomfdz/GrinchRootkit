OPTS=-Wall -fPIC -shared -ldl

all:
	gcc -o grinch.so grinch.c ${OPTS}
	chmod 4755 grinch.so

clean:
	rm grinch.so
