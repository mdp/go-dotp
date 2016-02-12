all: clean realease clean

bump:
	cd cli/dotp; goxc bump; cd ../..

release:
	cd cli/dotp; goxc; cd ../..

clean:
	rm -rf cli/dotp/debian cli/dotp/releases

.PHONY: clean release bump
