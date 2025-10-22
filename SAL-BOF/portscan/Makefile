# AdaptixC2 - Smart Port Scanner BOF Makefile
# 智能端口扫描器BOF编译脚本

CC = x86_64-w64-mingw32-gcc
CFLAGS = -Os -s -c -DBOF -I../_include

# 源文件
SRCS = portscan_simple.c
TARGET = portscan.x64.o

# 编译规则
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $<
	x86_64-w64-mingw32-strip --strip-unneeded $@

# 清理
clean:
	rm -f $(TARGET)

# 安装
install:
	mkdir -p ../_bin
	cp $(TARGET) ../_bin/portscan.x64.o

# 卸载
uninstall:
	rm -f ../_bin/portscan.x64.o

.PHONY: all clean install uninstall