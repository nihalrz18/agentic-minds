"""
Scanner Agent — Phase 1 of SwarmAudit.
Clones the target GitHub repository and maps its structure and tech stack.
"""
import os
import re
import shutil
from pathlib import Path
from typing import Dict, Any, List

import git

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "target", "vendor", ".gradle",
    ".idea", ".vscode", "coverage", ".nyc_output", ".cache",
}

TECH_SIGNALS: Dict[str, List[str]] = {
    "Python":     [".py", "requirements.txt", "Pipfile", "setup.py", "pyproject.toml"],
    "JavaScript": [".js", ".jsx", "package.json"],
    "TypeScript": [".ts", ".tsx", "tsconfig.json"],
    "Java":       [".java", "pom.xml", "build.gradle"],
    "Go":         [".go", "go.mod"],
    "Rust":       [".rs", "Cargo.toml"],
    "Ruby":       [".rb", "Gemfile"],
    "PHP":        [".php", "composer.json"],
    "C#":         [".cs", ".csproj"],
    "C/C++":      [".c", ".cpp", ".h", ".hpp"],
    "Swift":      [".swift"],
    "Kotlin":     [".kt"],
    "Dockerfile": ["Dockerfile", "docker-compose.yml"],
    "Terraform":  [".tf", ".tfvars"],
    "Shell":      [".sh", ".bash"],
    "YAML/Config":[".yml", ".yaml"],
}

FRAMEWORK_SIGNALS: Dict[str, List[str]] = {
    "Django":      ["django", "DJANGO_SETTINGS_MODULE", "from django"],
    "Flask":       ["from flask", "import flask", "Flask(__name__)"],
    "FastAPI":     ["from fastapi", "import fastapi", "FastAPI()"],
    "React":       ['"react"', "'react'", '"react-dom"'],
    "Vue":         ['"vue"', "vue.config.js"],
    "Angular":     ['"@angular/core"'],
    "Next.js":     ['"next"', "next.config.js"],
    "Express":     ['"express"', "require('express')", "require(\"express\")"],
    "Spring Boot": ["spring-boot", "SpringApplication", "@SpringBootApplication"],
    "Laravel":     ["illuminate/foundation", "Illuminate\\Foundation"],
    "Rails":       ["rails/all", "ActionController::Base"],
    "NestJS":      ['"@nestjs/core"'],
}


class ScannerAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config

    def run(self, github_url: str) -> Dict[str, Any]:
        try:
            # Validate and parse URL
            match = re.match(
                r"https://github\.com/([^/]+)/([^/\s]+?)(?:\.git)?(?:/.*)?$",
                github_url.strip(),
            )
            if not match:
                return {"error": "Invalid GitHub URL format", "scan_complete": False}

            owner = match.group(1)
            repo_name = match.group(2).rstrip("/")
            safe_owner = re.sub(r"[^a-zA-Z0-9_-]", "_", owner)[:16]
            safe_repo  = re.sub(r"[^a-zA-Z0-9_-]", "_", repo_name)[:32]
            clone_path = f"/tmp/swarmaudit_{safe_owner}_{safe_repo}"

            # Remove stale clone
            if os.path.exists(clone_path):
                shutil.rmtree(clone_path, ignore_errors=True)

            # Shallow clone for speed
            try:
                git.Repo.clone_from(
                    github_url,
                    clone_path,
                    depth=1,
                    multi_options=["--single-branch"],
                )
            except git.exc.GitCommandError as exc:
                err = str(exc).lower()
                if "not found" in err or "repository" in err or "403" in err:
                    return {
                        "error": f"Repository not found or is private: {github_url}",
                        "scan_complete": False,
                    }
                raise

            # Walk repository
            file_tree: List[str] = []
            languages: Dict[str, int] = {}
            config_files: List[str] = []
            dependency_files: List[str] = []
            total_size = 0

            DEP_FILES = {
                "requirements.txt", "package.json", "pom.xml",
                "go.mod", "Cargo.toml", "Gemfile", "composer.json",
                "pyproject.toml", "Pipfile", "yarn.lock",
            }
            CONFIG_FILES = {
                ".env", ".env.example", "config.yml", "config.yaml",
                "settings.py", "application.properties", "application.yml",
                "Dockerfile", "docker-compose.yml", "nginx.conf",
                ".github", "webpack.config.js", "babel.config.js",
            }

            for root, dirs, files in os.walk(clone_path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    rel   = os.path.relpath(fpath, clone_path)
                    try:
                        fsize = os.path.getsize(fpath)
                    except OSError:
                        fsize = 0
                    total_size += fsize
                    if fsize > 1_000_000:   # Skip files > 1 MB
                        continue
                    file_tree.append(rel)
                    ext = Path(fname).suffix.lower()
                    if ext:
                        languages[ext] = languages.get(ext, 0) + 1
                    if fname in DEP_FILES:
                        dependency_files.append(rel)
                    if fname in CONFIG_FILES:
                        config_files.append(rel)

            tech_stack = self._detect_tech_stack(clone_path, file_tree)
            size_mb = round(total_size / (1024 * 1024), 2)

            return {
                "repo_url":        github_url,
                "repo_name":       repo_name,
                "owner":           owner,
                "clone_path":      clone_path,
                "file_count":      len(file_tree),
                "file_tree":       file_tree[:500],
                "tech_stack":      tech_stack,
                "languages":       languages,
                "config_files":    config_files,
                "dependency_files": dependency_files,
                "size_mb":         size_mb,
                "size_warning":    size_mb > 50,
                "scan_complete":   True,
            }

        except Exception as exc:
            return {"error": str(exc), "scan_complete": False}

    # ──────────────────────────────────────────────────────────────────────────
    def _detect_tech_stack(self, clone_path: str, file_tree: List[str]) -> List[str]:
        detected: set = set()
        fname_set  = {os.path.basename(f) for f in file_tree}
        all_exts   = {Path(f).suffix.lower() for f in file_tree}

        for tech, signals in TECH_SIGNALS.items():
            for sig in signals:
                if sig.startswith(".") and sig in all_exts:
                    detected.add(tech)
                    break
                elif not sig.startswith(".") and sig in fname_set:
                    detected.add(tech)
                    break

        # Deep-check framework signals in key files
        for check_file in ("package.json", "requirements.txt", "pom.xml", "go.mod"):
            full = os.path.join(clone_path, check_file)
            if not os.path.exists(full):
                continue
            try:
                content = open(full, encoding="utf-8", errors="ignore").read()
                for framework, sigs in FRAMEWORK_SIGNALS.items():
                    if any(s in content for s in sigs):
                        detected.add(framework)
            except OSError:
                pass

        return sorted(detected)
