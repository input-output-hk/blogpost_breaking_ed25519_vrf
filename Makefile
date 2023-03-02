ifeq ($(shell uname),Darwin)
	    LDFLAGS := -Wl,-dead_strip -lsodium
    else
	    LDFLAGS := -Wl,--gc-sections -lpthread -ldl -lsodium

    endif

run:
	$(CC) $(LDFLAGS)  main.c -o test

clean:
	rm test