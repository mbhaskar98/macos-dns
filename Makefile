remove:
	echo "Build is starting"
	rm -rf build dist setup.py
build:remove
	py2applet --make-setup SimpleDNSServer.py
	python setup.py py2app -A

