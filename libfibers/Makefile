SRC = 	thread.c \
		libfibers.c
		
CFLAGS = -O3
EXEC = libfibers
OBJS := $(SRC:%.c=%.o)
OBJS := $(OBJS:%.S=%.o)
OBJS := $(OBJS:%.c=%.so)
LIBS = -lm -lpthread

all: #$(EXEC)
	gcc -O3 -c -Wall -Werror -fomit-frame-pointer -fpic libfibers.c
	gcc -O3 -shared -o libfibers.so libfibers.o

install:
	cp libfibers.so /usr/lib
	chmod 0755 /usr/lib/libfibers.so
	ldconfig

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $(EXEC)

%.o : %.S
	$(CC) $< $(LIBS) -c -o $@

.PHONY: clean
clean:
	-rm $(OBJS)
	-rm $(EXEC)
