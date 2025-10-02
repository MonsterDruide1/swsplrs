all: assemble link nso copy

assemble:
	bash -c 'for f in asm/*.s; do aarch64-linux-gnu-as -o "obj/$$(basename "$${f%.s}.o")" "$$f"; done'
link:
	aarch64-linux-gnu-ld -o myprog obj/*.o -T ldscript.lcf --no-warn-mismatch --no-check-sections -w
nso:
	cargo run --manifest-path ~/elf2nso/Cargo.toml myprog -o myprog.un.nso --build-id 3CA12DFAAF9C82DA064D1698DF79CDA100000000000000000000000000000000
copy:
	cp myprog /mnt/d/
	cp myprog.un.nso /mnt/d/
