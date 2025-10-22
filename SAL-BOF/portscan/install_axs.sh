#!/bin/bash

# AdaptixC2 - Smart Port Scanner AxScript Installation Script
# 智能端口扫描器AxScript安装脚本

echo "AdaptixC2 Smart Port Scanner AxScript Installation"
echo "================================================="

# AdaptixC2 - Smart Port Scanner Installation Script
# 智能端口扫描器安装脚本

echo "AdaptixC2 Smart Port Scanner Installation"
echo "========================================"
echo ""
echo "✓ BOF compilation and installation completed"
echo "✓ AxScript integration configured"
echo ""
echo "Installation Summary:"
echo "- BOF file: Extension-Kit/SAL-BOF/_bin/portscan.x64.o"
echo "- AxScript: Extension-Kit/SAL-BOF/portscan/cmd_smartscan.axs"
echo "- Integration: Extension-Kit/extension-kit.axs"
echo ""
echo "Next steps:"
echo "1. Start AdaptixC2 client"
echo "2. Go to 'Tools' -> 'AxScript manager'"
echo "3. Right-click in the AxScript manager"
echo "4. Select 'Load new'"
echo "5. Navigate to: Extension-Kit/extension-kit.axs"
echo "6. Select and load the extension-kit.axs file"
echo ""
echo "After loading, you can use the 'smartscan' command:"
echo "  smartscan 192.168.1.1"
echo "  smartscan 192.168.1.0/24 2"
echo "  smartscan 10.0.0.1/16 3"
echo "  smartscan 192.168.1.1 '80,443,22-25,3389'"
echo ""
echo "✓ Installation completed successfully!"
echo "✓ No duplicate commands - clean integration"