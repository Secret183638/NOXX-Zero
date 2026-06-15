CXX = clang++
CXXFLAGS = -O3 -ffast-math -march=native -mtune=native -flto=thin -funroll-loops -fomit-frame-pointer -o noxx-zero nz.cpp -std=c++17
TARGET = noxx-zero
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

fast: $(SRC)
	$(CXX) -O3 -march=native -mtune=native -flto=thin -s -o $(TARGET) $(SRC) -std=c++17

debug: $(SRC)
	$(CXX) -g -O0 -o $(TARGET) $(SRC) -std=c++17

strip: $(TARGET)
	strip --strip-all $(TARGET)
	@echo "Binary size: $$(ls -lh $(TARGET) | awk '{print $$5}')"

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

test: $(TARGET)
	@echo "Test" > test.txt
	./$(TARGET) -c test.txt test.enc
	./$(TARGET) -d test.enc test.dec
	@diff test.txt test.dec && echo "✅ Test passed" || echo "❌ Test failed"
	@rm -f test.txt test.enc test.dec

info: $(TARGET)
	@echo "Binary: $(TARGET)"
	@echo "Size: $$(ls -lh $(TARGET) | awk '{print $$5}')"
	@echo "Deps: $$(ldd $(TARGET) 2>/dev/null || echo "static or no deps")"

help:
	@echo "Targets:"
	@echo "  make        - Build (optimized + stripped)"
	@echo "  make fast   - Build with native optimizations"
	@echo "  make debug  - Build with debug symbols"
	@echo "  make strip  - Strip binary"
	@echo "  make test   - Run encryption/decryption test"
	@echo "  make info   - Show binary info"
	@echo "  make install- Copy to /usr/local/bin"
	@echo "  make clean  - Remove binary"

.PHONY: all fast debug strip clean install uninstall test info help
