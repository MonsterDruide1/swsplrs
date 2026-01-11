-include Makefile.secret
all: clean cxxstubs missingfunctions assemble link copy send

toolchain = $(PWD)/../data/
lld = $(toolchain)ld.lld
clang = $(toolchain)clang -target aarch64-linux-gnu -nostdlib -fuse-ld=$(lld)

lld = aarch64-linux-gnu-ld
clang = aarch64-linux-gnu-gcc -nostdlib

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
	$(lld) -o myprog obj/*.o -T ../assets/ldscript.lcf -L. -lsdk -lsubsdk0 --warn-unresolved-symbols -pie --hash-style=both --dynamic-list=asm/exported_symbols.sym --eh-frame-hdr 2>&1 | sed '/warning: undefined symbol: glslc/,+2d'
	cargo run --manifest-path ~/elf2nso/Cargo.toml myprog -o myprog.un.nso --build-id 3CA12DFAAF9C82DA064D1698DF79CDA100000000000000000000000000000000
linkwithdecomp:
	$(lld) -o myprog $(shell find ~/OdysseyDecomp/build/CMakeFiles/odyssey.dir -name "*.obj" ! -path "*/al/Library/Play/Camera/CameraVerticalAbsorber.cpp.obj" ! -path "*/al/Library/Base/StringUtil.cpp.obj" ! -path "*al/Library/Resource/Resource.cpp.obj" ! -path "*Factory.cpp.obj") obj/*.o -T ../assets/ldscript.lcf -rpath=$PWD -L. -lsdk -lsubsdk0 -lglslc -pie -z now --allow-multiple-definition --dynamic-list=asm/exported_symbols.sym
	cargo run --manifest-path ~/elf2nso/Cargo.toml myprog -o myprog.un.nso --build-id 5110ABCDEF0123456789ABCDEF01234500000000000000000000000000000000
#	linkwithdecomp:
#	$(lld) -o myprog $(shell find ~/OdysseyDecomp/build/CMakeFiles/odyssey.dir -name "*.obj" ! -path "*/al/Library/Base/StringUtil.cpp.obj" ! -path "*/al/Library/LiveActor/LiveActorKeeper.cpp.obj" ! -path "*al/Library/Resource/Resource.cpp.obj" ! -path "*Factory.cpp.obj") obj/*.o -T ../assets/ldscript.lcf -rpath=$PWD -L. -lsdk -lsubsdk0 -lglslc -pie -z now --allow-multiple-definition --dynamic-list=asm/exported_symbols.sym 2>&1 | sed '/warning: duplicate symbol:/,+4d'
#	$(lld) -o myprog $(shell find ~/OdysseyDecomp/build/CMakeFiles/odyssey.dir -name "*.obj" ! -path "*/al/Library/Play/Layout/SimpleLayoutAppearWaitEnd.cpp.obj" ! -path "*/src/Scene/StageSceneStatePauseMenu.cpp.obj" ! -path "*/src/Scene/TitleMenuScene.cpp.obj" ! -path "*/al/Library/Base/StringUtil.cpp.obj" ! -path "*/al/Library/LiveActor/LiveActorKeeper.cpp.obj" ! -path "*al/Library/Resource/Resource.cpp.obj" ! -path "*Factory.cpp.obj") obj/*.o -T ../assets/ldscript.lcf -rpath=$PWD -L. -lsdk -lsubsdk0 -lglslc -pie -z now --allow-multiple-definition --dynamic-list=asm/exported_symbols.sym 2>&1 | sed '/warning: duplicate symbol:/,+4d'
copy:
	cp myprog /mnt/d/
	cp myprog.un.nso /mnt/d/
send:
	ncftpput -C -u ${FTP_USER} -p ${FTP_PASS} -P 5000 ${FTP_IP} myprog.un.nso /atmosphere/contents/${TITLE_ID}/exefs/main
