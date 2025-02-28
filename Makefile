LHA_COMMAND = $(shell pwd)/lha/src/lha

all:
	@echo "Usage: make test"

test: $(LHA_COMMAND)
	./test.py --lha $(LHA_COMMAND) --method lh0
	./test.py --lha $(LHA_COMMAND) --method lh1
	./test.py --lha $(LHA_COMMAND) --method lh5
	./test.py --lha $(LHA_COMMAND) --method lh6
	./test.py --lha $(LHA_COMMAND) --method lh7
	-rm -rf /tmp/unlha

$(LHA_COMMAND):
	./unlha.py x lha_source.lzh
	(cd lha; aclocal && autoheader && automake -a && autoconf)
	(cd lha; ./configure && make)

clean:
	-rm -rf lha __pycache__
