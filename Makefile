.PHONY: all clean

TARGET=poc

SOURCES = $(wildcard src/*.c)
HEADERS = $(wildcard inc/*.h)
OBJECTS = $(patsubst src/%.c,obj/%.o,$(SOURCES))

CFLAGS= -I./inc
LDFLAGS= -static

all: obj $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

obj/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

obj:
	mkdir obj

clean:
	rm -rf obj/*.o
	rm -f $(TARGET)
