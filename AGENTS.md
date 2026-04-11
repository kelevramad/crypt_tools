# Repository Guidelines

## Project Structure & Module Organization
This repository is organized around two top-level CLI implementations: `crypt_tools.py` for Python and `crypt_tools.js` for Node.js. Shared Shamir helpers live in `shamir.py` and `shamir.js`. Tests are consolidated under `tests/`, with Python tests named `test_*.py` and Node tests named `*.test.js`. Build artifacts such as `dist/`, `build/`, `coverage/`, and `htmlcov/` should be treated as generated output, not hand-edited source.

## Build, Test, and Development Commands
Use the toolchain that matches the entrypoint you are changing.

- `uv sync`: install Python dependencies from `pyproject.toml` and `uv.lock`.
- `uv run pytest`: run the Python test suite with verbose output and coverage enabled by `pytest.ini`.
- `uv run ruff check .`: lint Python files.
- `uv run ruff format .`: format Python files.
- `npm install`: install Node dependencies from `package.json`.
- `npm test`: run the Node test suite with `node --test`.
- `npm run coverage`: collect Node coverage via `c8`.

## Build Executable Command
When the user asks to build a new version, run these commands in sequence:

1. Update version in scripts:
   - `crypt_tools.py`: Update `Config.VERSION` in the `Config` class
   - `crypt_tools.js`: Update `Config.VERSION` in the `Config` class

2. Update docs:
   - `PRD.md`: Update version in "Executive Summary" table
   - `README.md`: Update version in "Technical Details" section
   - `README_NODEJS.md`: Update version in "Technical Details" section

3. Update `version_info.txt` with new version number

4. Build the exe file:
```bash
uvx --with pycryptodome --with tqdm pyinstaller --onefile --icon=favicon.ico --version-file=version_info.txt crypt_tools.py
```

5. Copy exe to root:
```bash
cp ./dist/crypt_tools.exe .
```

6. Push and sync to git

7. Create a new GitHub release

## Coding Style & Naming Conventions
Keep changes small and CLI-focused. Python formatting follows Ruff settings in `pyproject.toml`: 100-character line length, single quotes, and tabs for indentation. Python tests and functions use `snake_case`; classes use `PascalCase`. In JavaScript, match the existing file style in `crypt_tools.js` and `tests/*.test.js`; current tests use semicolons, `const`, and 2-space indentation. Name new tests after the behavior they validate, for example `test_hidden_volume_roundtrip` or `hidden volume decrypts with inner password`.

## Testing Guidelines
Add or update tests for every user-visible CLI change, especially around encryption format, hidden volumes, wildcards, error handling, and default values (e.g., `--generate-keyfile` defaults to `key.txt`). Prefer targeted runs while iterating, then finish with both suites: `uv run pytest` and `npm test`. Python coverage is already wired through `pytest --cov=crypt_tools`; do not merge features that reduce exercised paths without a reason.

## Commit & Pull Request Guidelines
Recent history uses Conventional Commit prefixes such as `feat:`, `test:`, and `chore:`. Follow that format and keep subjects specific, for example `feat: add hidden footer validation`. Pull requests should explain the user-facing change, list test commands you ran, and call out any format or compatibility impact. Include terminal output snippets only when they clarify CLI behavior.

## Release Automation Guidelines
When creating GitHub releases, always follow this structure:

### 1. Title:
- Format: `v<version> - <short summary>`

### 2. Overview:
- 1–2 sentences explaining the purpose of this release.

### 3. 🚀 Features
- List new features with concise bullet points.

### 4. 🛠 Improvements
- Enhancements or optimizations.

### 5. 🐛 Bug Fixes
- Clearly describe fixes.

### 6. 🔐 Security
- Mention any cryptography/security updates.

### 7. ⚠️ Breaking Changes (if any)
- Clearly warn users.

### 8. 📦 CLI Usage (if relevant)
- Show updated commands or examples.

### 9. 📊 Full Changelog
- Format: `<previous_version>...<current_version>`

### 10. 👥 Contributors (optional)

**Rules:**
- Keep it concise but professional.
- Use emojis for sections.
- Use markdown formatting.
- Always maintain the same structure.
- Never omit sections (write "None" if empty).

Use `gh release create v<version> --title "v<version> - <summary>" --notes "<markdown>"` to create releases.
