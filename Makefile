.PHONY: all skiptest deps compile eunit test doc clean distclean

REBAR=rebar

all: compile eunit

skip_test: compile

deps:
	$(REBAR) get-deps

compile: deps
	$(REBAR) compile

eunit: compile
	$(REBAR) eunit skip_deps=true

test: eunit

doc: compile
	$(REBAR) doc skip_deps=true

clean:
	$(REBAR) clean
	rm -rf priv ebin

distclean: clean
	rm -rf deps
