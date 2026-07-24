```markdown
# slipstream Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `slipstream` Python codebase. It covers file organization, code style, commit message conventions, and testing patterns, providing a clear guide for contributing to or maintaining the project.

## Coding Conventions

### File Naming
- Use **snake_case** for all filenames.
  - Example: `data_processor.py`, `user_utils.py`

### Import Style
- Prefer **relative imports** within the package.
  - Example:
    ```python
    from .utils import helper_function
    ```

### Export Style
- Use **named exports** (explicitly define what is exported).
  - Example:
    ```python
    __all__ = ['MyClass', 'my_function']
    ```

### Commit Messages
- Follow **conventional commit** format.
- Use the `build` prefix for build-related changes.
  - Example:
    ```
    build: update requirements for new dependency
    ```

## Workflows

### Build Workflow
**Trigger:** When updating dependencies or making changes affecting the build process  
**Command:** `/build`

1. Update dependencies or build scripts as needed.
2. Ensure all changes are reflected in the appropriate files (e.g., `requirements.txt`).
3. Commit changes using the `build:` prefix in the commit message.
   - Example: `build: upgrade numpy to v1.24.0`
4. Run tests to verify build integrity.

## Testing Patterns

- Test files follow the `*.test.*` naming pattern.
  - Example: `data_processor.test.py`
- The testing framework is **unknown**; check existing test files for structure.
- Place tests alongside or near the modules they test.

**Example test file:**
```python
# data_processor.test.py

from .data_processor import process_data

def test_process_data():
    assert process_data([1, 2, 3]) == [2, 3, 4]
```

## Commands
| Command   | Purpose                                               |
|-----------|-------------------------------------------------------|
| /build    | Run the build workflow after dependency or build changes |
```
