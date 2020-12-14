run:
	rm -f httpd.pid
	LD_LIBRARY_PATH=../../libs7e \
	    httpd -DFOREGROUND -f httpd.conf -c "DocumentRoot $(CURDIR)"
