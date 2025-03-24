#!/bin/bash
# 运行所有示例脚本
# 用法: ./run_all.sh

set -e  # 遇到错误立即退出

EXAMPLES_DIR=$(dirname "$0")
cd "$EXAMPLES_DIR"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}开始运行所有示例...${NC}"
echo

# 查找并运行所有示例目录中的main.go文件
for dir in */; do
  if [ -f "${dir}main.go" ]; then
    echo -e "${YELLOW}======================================${NC}"
    echo -e "${GREEN}运行示例: ${dir%/}${NC}"
    echo -e "${YELLOW}======================================${NC}"
    
    # 进入目录运行示例
    (cd "$dir" && go run main.go)
    
    # 检查运行状态
    if [ $? -eq 0 ]; then
      echo -e "\n${GREEN}✓ 示例 ${dir%/} 运行成功${NC}\n"
    else
      echo -e "\n${RED}✗ 示例 ${dir%/} 运行失败${NC}\n"
      exit 1
    fi
    
    echo
  fi
done

echo -e "${GREEN}所有示例运行完成!${NC}" 