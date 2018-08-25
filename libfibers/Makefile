SRC = 	thread.c \
		libfibers.c
		
CFLAGS = -O3
EXEC = libfibers
OBJS := $(SRC:%.c=%.o)
OBJS := $(OBJS:%.S=%.o)
LIBS = -lm -lpthread

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $(EXEC)

%.o : %.S
	$(CC) $< $(LIBS) -c -o $@

.PHONY: clean
clean:
	-rm $(OBJS)
	-rm $(EXEC)
