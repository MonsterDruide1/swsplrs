-include Makefile.secret
all: clean cxxstubs missingfunctions assemble link nso copy send

toolchain = ../data/
clang = $(toolchain)clang -target aarch64-linux-gnu -nostdlib
lld = $(toolchain)ld.lld

clean:
	rm -r obj || true
	rm myprog || true
	rm myprog.nso || true
	rm myprog.un.nso || true
glslc:
	$(clang) -shared -o libglslc.so -fPIC ../assets/glslcStubs.c
cxxstubs:
	mkdir -p obj
	$(clang) -c -o obj/cxxstubs.o ../assets/cxxstubs.c
missingfunctions:
	mkdir -p obj
	$(clang) -c -o obj/missingfunctions.o ../assets/missingfunctions.cpp
assemble:
	mkdir -p obj
	bash -c 'for f in asm/*.s; do $(clang) -c -o "obj/$$(basename "$${f%.s}.o")" "$$f"; done'
link:
	$(lld) -o myprog obj/*.o -T ../assets/ldscript.lcf -rpath=$PWD -L. -lsdk -lsubsdk0 -lglslc -pie -z now --hash-style=both
linkwithdecomp:
	$(lld) -o myprog $(shell find ~/OdysseyDecomp/build/CMakeFiles/odyssey.dir -name "*.obj" ! -path "*/al/Library/LiveActor/LiveActorKeeper.cpp.obj" ! -path "*al/Library/Resource/Resource.cpp.obj" ! -path "*Factory.cpp.obj") obj/*.o -T ../assets/ldscript.lcf -rpath=$PWD -L. -lsdk -lsubsdk0 -lglslc -pie -z now --allow-multiple-definition
nso:
	cargo run --manifest-path ~/elf2nso/Cargo.toml myprog -o myprog.un.nso --build-id 3CA12DFAAF9C82DA064D1698DF79CDA100000000000000000000000000000000
copy:
	cp myprog /mnt/d/
	cp myprog.un.nso /mnt/d/
send:
	ncftpput -C -u ${FTP_USER} -p ${FTP_PASS} -P 5000 ${FTP_IP} myprog.un.nso /atmosphere/contents/${TITLE_ID}/exefs/main
