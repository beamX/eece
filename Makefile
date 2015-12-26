PROJECT = eece
PROJECT_DESCRIPTION = New project
PROJECT_VERSION = 0.0.1

DEPS = hkdf base64url

dep_hkdf = git https://github.com/schnef/hkdf master
dep_base64url = git https://github.com/dvv/base64url master

include erlang.mk

console:
	erl -pa deps/*/ebin/ ebin/
