setup: data/file_list.yml data/main.nso data/sdk data/subsdk0 data/nx2elf data/clang data/ld.lld out

relink: setup out/Makefile out/libsdk.so out/libsubsdk0.so out/libglslc.so
	cargo run -- --export-relinkable --game SMO data/main.nso
	cd out && make assemble link

objdiff: setup
	cargo run -- --split --objdiff --game SMO data/main.nso

clean:
	rm -r out || true


# setup stuff
data/file_list.yml:  # not downloaded automatically to tell the user => might have to be updated later
	$(error Download file list from https://github.com/MonsterDruide1/OdysseyDecomp/raw/refs/heads/master/data/file_list.yml and put it into data/file_list.yml)
data/main.nso:
	$(error Put SMO 1.0's main.nso into data/main.nso)
data/sdk:
	$(error Put SMO 1.0's sdk into data/sdk)
data/subsdk0:
	$(error Put SMO 1.0's subsdk0 into data/subsdk0)
data/nx2elf:
	$(error Put nx2elf into data/nx2elf. It can be found in OdysseyDecomp's toolchain folder (toolchain/bin/nx2elf), or can be built from https://github.com/shuffle2/nx2elf)
data/clang:
	$(error Put clang 5.0.0 into data/clang. It can be downloaded from https://releases.llvm.org/)
data/ld.lld:
	$(error Put lld 5.0.0 into data/ld.lld. It can be downloaded from https://releases.llvm.org/)
out:
	mkdir -p out

out/Makefile: out
	cp assets/Makefile out/Makefile
out/libsdk.so: out data/sdk data/nx2elf
	data/nx2elf data/sdk
	mv data/sdk.elf out/libsdk.so
out/libsubsdk0.so: out data/subsdk0 data/nx2elf
	data/nx2elf data/subsdk0
	mv data/subsdk0.elf out/libsubsdk0.so
out/libglslc.so: out out/Makefile
	cd out && make glslc
