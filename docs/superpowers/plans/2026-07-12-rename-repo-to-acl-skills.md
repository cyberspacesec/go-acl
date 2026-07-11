# 仓库重命名为 acl-skills Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将 GitHub 仓库 `cyberspacesec/go-acl` 重命名为 `cyberspacesec/acl-skills`，并同步更新本地文件夹名与 Go 代码中的所有 module/import 路径，使本地与远程完全一致。

**Architecture:** 远程仓库重命名（gh repo rename）→ 批量替换所有源码/文档中的 module 前缀 `github.com/cyberspacesec/go-acl` → `github.com/cyberspacesec/acl-skills` → 更新 `go.mod` 的 module 声明 → `go build`/`go test` 验证编译与测试通过 → 重命名本地文件夹 `go-acl` → `acl-skills` → 更新 git remote URL → 提交并推送。数据流是单向的：先改代码（保证本地可编译），再动文件夹和 remote，避免中途状态不可编译。

**Tech Stack:** Go 1.18+ (go.mod module path), Git 2.x, GitHub CLI (gh) 2.x, Bash

**Risks:**
- Task 2 批量替换 24 个 .go/.md 文件，可能误伤非模块路径的 `go-acl` 字样 → 缓解：用精确字面量 `github.com/cyberspacesec/go-acl` 全文替换；README 中的横幅/徽章路径单独用 `cyberspacesec/go-acl` → `cyberspacesec/acl-skills` 替换，逐处确认
- Task 5 重命名本地文件夹时若处于该目录内会失败 → 缓解：在父目录 `cyberspacesec/` 下执行 `mv go-acl acl-skills`
- gh repo rename 后旧 remote URL 仍可重定向，但显式更新更清晰 → 缓解：rename 后立即 `git remote set-url`
- 重命名文件夹后 IDE/终端当前工作目录失效 → 缓解：脚本末尾提示用户重新 `cd`

---

### Task 1: 重命名 GitHub 远程仓库

**Depends on:** None
**Files:**
- Modify: GitHub remote repository `cyberspacesec/go-acl` → `cyberspacesec/acl-skills`

- [ ] **Step 1: 确认 gh 已认证且当前仓库正确**
Run: `gh auth status && gh repo view --json name,nameWithOwner`
Expected:
  - Exit code: 0
  - Output contains: `CC11001100`（认证账户）和 `"nameWithOwner":"cyberspacesec/go-acl"`

- [ ] **Step 2: 重命名远程仓库 — 将 go-acl 改为 acl-skills**
Run: `gh repo rename acl-skills --repo cyberspacesec/go-acl --yes`
Expected:
  - Exit code: 0
  - Output contains: `cyberspacesec/acl-skills`（重命名成功后的仓库全名）

- [ ] **Step 3: 验证远程仓库新名称生效**
Run: `gh repo view cyberspacesec/acl-skills --json name,nameWithOwner,url`
Expected:
  - Exit code: 0
  - Output contains: `"nameWithOwner":"cyberspacesec/acl-skills"` 和 `"url":"https://github.com/cyberspacesec/acl-skills"`

---

### Task 2: 批量替换 Go 源码与文档中的模块路径

**Depends on:** Task 1
**Files:**
- Modify: `go.mod`（module 声明）
- Modify: 22 个 `.go` 文件的 import 语句（`pkg/` 与 `examples/` 下）
- Modify: `README.md`、`examples/README.md` 中的 import 示例与链接

- [ ] **Step 1: 替换所有 .go 文件中的 module 前缀 — 把 import 路径对齐新仓库名**
Run: `grep -rl --include="*.go" "github.com/cyberspacesec/go-acl" . | xargs sed -i 's|github.com/cyberspacesec/go-acl|github.com/cyberspacesec/acl-skills|g'`
Expected:
  - Exit code: 0
  - 之后再执行 `grep -rn --include="*.go" "cyberspacesec/go-acl" .` 应无输出

- [ ] **Step 2: 替换 go.mod 的 module 声明 — 对齐新仓库名**
Run: `sed -i 's|github.com/cyberspacesec/go-acl|github.com/cyberspacesec/acl-skills|g' go.mod`
Expected:
  - Exit code: 0
  - `head -1 go.mod` 输出为 `module github.com/cyberspacesec/acl-skills`

- [ ] **Step 3: 替换 README.md 中的徽章、横幅、go get 与 import 示例路径**
Run: `sed -i 's|cyberspacesec/go-acl|cyberspacesec/acl-skills|g' README.md`
Expected:
  - Exit code: 0
  - `grep -n "cyberspacesec/go-acl" README.md` 应无输出
  - `grep -n "cyberspacesec/acl-skills" README.md` 应有多行输出（含徽章、横幅、go get、import）

- [ ] **Step 4: 替换 examples/README.md 中的 pkg.go.dev 与 issues 链接**
Run: `sed -i 's|cyberspacesec/go-acl|cyberspacesec/acl-skills|g' examples/README.md`
Expected:
  - Exit code: 0
  - `grep -n "cyberspacesec/go-acl" examples/README.md` 应无输出

- [ ] **Step 5: 验证全仓库无残留旧路径**
Run: `grep -rn "cyberspacesec/go-acl" --include="*.go" --include="*.md" --include="*.mod" --include="*.yml" --include="*.yaml" . | grep -v "/.git/" || echo "NO_RESIDUE"`
Expected:
  - Exit code: 0
  - Output contains: `NO_RESIDUE`

---

### Task 3: 验证编译与测试

**Depends on:** Task 2
**Files:**
- Modify: 无（仅运行验证）

- [ ] **Step 1: 同步依赖 — 校验 go.mod 一致性**
Run: `go mod tidy`
Expected:
  - Exit code: 0
  - 无报错输出

- [ ] **Step 2: 验证全项目编译通过**
Run: `go build ./...`
Expected:
  - Exit code: 0
  - 无报错输出

- [ ] **Step 3: 验证单元测试通过**
Run: `go test ./... 2>&1 | tail -30`
Expected:
  - Exit code: 0
  - Output contains: `ok`（各包均通过）
  - Output does NOT contain: `FAIL` 或 `cannot find module`

---

### Task 4: 提交代码变更

**Depends on:** Task 3
**Files:**
- Modify: `go.mod`、22 个 `.go` 文件、`README.md`、`examples/README.md`

- [ ] **Step 1: 暂存并提交所有路径替换变更**
Run: `git add -A && git commit -m "refactor: rename module path from go-acl to acl-skills

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`
Expected:
  - Exit code: 0
  - `git log -1 --oneline` 输出包含 `acl-skills`

---

### Task 5: 重命名本地文件夹、更新 git remote 并推送

**Depends on:** Task 4
**Files:**
- Modify: 本地文件夹 `cyberspacesec/go-acl` → `cyberspacesec/acl-skills`
- Modify: git remote origin URL

- [ ] **Step 1: 更新 git remote URL — 指向新仓库名（SSH 形式）**
Run: `git remote set-url origin git@github.com:cyberspacesec/acl-skills.git && git remote -v`
Expected:
  - Exit code: 0
  - Output contains: `git@github.com:cyberspacesec/acl-skills.git`（fetch 与 push 均为此 URL）

- [ ] **Step 2: 推送代码到新远程仓库 — 同步本地提交**
Run: `git push -u origin main`
Expected:
  - Exit code: 0
  - Output contains: `main -> main` 或 `Everything up-to-date`

- [ ] **Step 3: 重命名本地文件夹 — 与 GitHub 仓库名保持一致**
Run: `cd /home/cc11001100/github/cyberspacesec && mv go-acl acl-skills && ls -d acl-skills`
Expected:
  - Exit code: 0
  - Output contains: `acl-skills`

- [ ] **Step 4: 验证重命名后仓库状态正常**
Run: `cd /home/cc11001100/github/cyberspacesec/acl-skills && git status && git remote -v && head -1 go.mod`
Expected:
  - Exit code: 0
  - `git status` 输出 `nothing to commit, working tree clean`
  - `git remote -v` 输出含 `cyberspacesec/acl-skills`
  - `head -1 go.mod` 输出 `module github.com/cyberspacesec/acl-skills`
