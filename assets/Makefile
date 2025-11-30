-include Makefile.secret
all: clean assemble link nso copy send

clean:
	rm -r obj || true
	rm myprog || true
	rm myprog.nso || true
	rm myprog.un.nso || true
glslc:
	aarch64-linux-gnu-gcc -shared -o libglslc.so -fPIC glslcStubs.c
assemble:
	mkdir -p obj
	bash -c 'for f in asm/*.s; do aarch64-linux-gnu-as -o "obj/$$(basename "$${f%.s}.o")" "$$f"; done'
link:
	aarch64-linux-gnu-ld -o myprog obj/*.o -T ldscript.lcf -rpath=$PWD -L. -lsdk -lsubsdk0 -lglslc -pie -z now
nso:
	cargo run --manifest-path ~/elf2nso/Cargo.toml myprog -o myprog.un.nso --build-id 3CA12DFAAF9C82DA064D1698DF79CDA100000000000000000000000000000000
copy:
	cp myprog /mnt/d/
	cp myprog.un.nso /mnt/d/
send:
	ncftpput -C -u ${FTP_USER} -p ${FTP_PASS} -P 5000 ${FTP_IP} myprog.un.nso /atmosphere/contents/${TITLE_ID}/exefs/main
