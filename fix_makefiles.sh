#!/bin/bash

# 修复所有Makefile中的编译器标准问题
# 添加 -std=c11 到所有 x86_64-w64-mingw32-gcc 和 i686-w64-mingw32-gcc 调用

echo "正在修复Extension-Kit中的所有Makefile..."

# 查找所有Makefile文件
find . -name "Makefile" -type f | while read makefile; do
    echo "处理: $makefile"
    
    # 备份原文件
    cp "$makefile" "$makefile.backup"
    
    # 替换编译器调用，添加 -std=c11
    sed -i '' 's/x86_64-w64-mingw32-gcc /x86_64-w64-mingw32-gcc -std=c11 /g' "$makefile"
    sed -i '' 's/i686-w64-mingw32-gcc /i686-w64-mingw32-gcc -std=c11 /g' "$makefile"
    
    echo "已处理: $makefile"
done

echo "所有Makefile修复完成！"
echo "如果需要恢复，可以使用 .backup 文件"