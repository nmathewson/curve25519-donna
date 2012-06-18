targets: curve25519-donna.a curve25519-donna-sse2.a curve25519-donna-sse2-asm.a curve25519-donna-c64.a

test: test-donna test-donna-sse2 test-donna-sse2-asm test-donna-c64

clean:
	rm -f *.o *.a *.pp test-curve25519-donna test-curve25519-donna-sse2 test-curve25519-donna-sse2-asm test-curve25519-donna-c64 speed-curve25519-donna speed-curve25519-donna-sse2 speed-test-curve25519-donna-sse2-asm speed-curve25519-donna-c64 test-sc-curve25519-donna-c64


curve25519-donna.a: curve25519-donna.o
	ar -rc curve25519-donna.a curve25519-donna.o
	ranlib curve25519-donna.a

curve25519-donna.o: curve25519-donna.c
	gcc -O2 -c curve25519-donna.c -Wall -m32 -ggdb

curve25519-donna-sse2.a: curve25519-donna-sse2.o
	ar -rc curve25519-donna-sse2.a curve25519-donna-sse2.o

curve25519-donna-sse2.o: curve25519-donna-sse2.c
	gcc -O2 -c curve25519-donna-sse2.c -Wall -m32 -msse2 -ggdb

curve25519-donna-sse2-asm.a: curve25519-donna-sse2-asm.o
	ar -rc curve25519-donna-sse2-asm.a curve25519-donna-sse2-asm.o

curve25519-donna-sse2-asm.o: curve25519-donna-sse2-asm.s
	gcc -c curve25519-donna-sse2-asm.s -Wall -m32

curve25519-donna-c64.a: curve25519-donna-c64.o
	ar -rc curve25519-donna-c64.a curve25519-donna-c64.o
	ranlib curve25519-donna-c64.a

curve25519-donna-c64.o: curve25519-donna-c64.c
	gcc -O2 -c curve25519-donna-c64.c -Wall

test-donna: test-curve25519-donna

test-donna-sse2: test-curve25519-donna-sse2

test-donna-sse2-asm: test-curve25519-donna-sse2-asm

test-donna-c64: test-curve25519-donna-c64

test-curve25519-donna: test-curve25519.c curve25519-donna.a
	gcc -o test-curve25519-donna test-curve25519.c curve25519-donna.a -Wall -m32 -lssl

test-curve25519-donna-sse2: test-curve25519.c curve25519-donna-sse2.a
	gcc -o test-curve25519-donna-sse2 test-curve25519.c curve25519-donna-sse2.a -Wall -m32 -lssl

test-curve25519-donna-sse2-asm: test-curve25519.c curve25519-donna-sse2-asm.a
	gcc -o test-curve25519-donna-sse2-asm test-curve25519.c curve25519-donna-sse2-asm.a -Wall -m32 -lssl

test-curve25519-donna-c64: test-curve25519.c curve25519-donna-c64.a
	gcc -o test-curve25519-donna-c64 test-curve25519.c curve25519-donna-c64.a -Wall -lssl

speed-curve25519-donna: speed-curve25519.c curve25519-donna.a
	gcc -o speed-curve25519-donna speed-curve25519.c curve25519-donna.a -Wall -m32 -ggdb

speed-curve25519-donna-sse2: speed-curve25519.c curve25519-donna-sse2.a
	gcc -o speed-curve25519-donna-sse2 speed-curve25519.c curve25519-donna-sse2.a -Wall -m32 -ggdb

speed-curve25519-donna-sse2-asm: speed-curve25519.c curve25519-donna-sse2-asm.a
	gcc -o speed-curve25519-donna-sse2-asm speed-curve25519.c curve25519-donna-sse2-asm.a -Wall -m32 -ggdb

speed-curve25519-donna-c64: speed-curve25519.c curve25519-donna-c64.a
	gcc -o speed-curve25519-donna-c64 speed-curve25519.c curve25519-donna-c64.a -Wall

test-sc-curve25519-donna-c64: test-sc-curve25519.c curve25519-donna-c64.a
	gcc -o test-sc-curve25519-donna-c64 -O test-sc-curve25519.c curve25519-donna-c64.a -lm -Wall
