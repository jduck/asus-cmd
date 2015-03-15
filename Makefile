TARGET  = asus-cmd
CFLAGS += -Wall -Wextra -O2
SOURCES = $(wildcard *.c)

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf $(TARGET)
