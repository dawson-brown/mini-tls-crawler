testing:
	make -f makefile.test
	cp cacert.pem-example tests/cacert.pem

debugging:
	doxygen .doxygen
	make -f makefile.debug
	cp cacert.pem-example debug/cacert.pem

prod:
	doxygen .doxygen
	make -f makefile.prod

clean-test:
	rm tests/*.o
	rm tests/tests
	rm tests/cacert.pem

clean-debug:
	rm -rf docs/
	rm -rf debug/

clean-prod:
	rm -rf docs/
	rm -rf release/