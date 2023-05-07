ifdef DEBUG
	CFLAGS = -O0 -ggdb
else
	CFLAGS = -O2
endif

get-tdx-quote: get-tdx-quote.c
	$(CC) $(CFLAGS) $^ -ltdx_attest -o $@

clean:
	rm -rf get-tdx-quote
