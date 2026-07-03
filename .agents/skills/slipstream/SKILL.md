```markdown
# slipstream Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the development patterns and conventions used in the `slipstream` Python repository. It covers file naming, import/export styles, commit message practices, and testing patterns. While no specific workflows or frameworks are detected, this guide provides clear examples and suggested commands to streamline your development process in slipstream.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `dataProcessor.py`, `userManager.py`

### Import Style
- Use **relative imports** within the codebase.
  - Example:
    ```python
    from .utils import parseData
    from .models import User
    ```

### Export Style
- Use **named exports** (explicitly listing what is exported).
  - Example:
    ```python
    __all__ = ['parseData', 'User']
    ```

### Commit Messages
- No strict prefixing; commit messages are freeform.
- Average commit message length: ~35 characters.
  - Example:  
    ```
    Fix bug in data parsing logic
    ```

## Workflows

### Adding a New Module
**Trigger:** When you need to add a new feature or module to the codebase  
**Command:** `/add-module`

1. Create a new Python file using camelCase naming (e.g., `featureModule.py`).
2. Implement your functions/classes.
3. Use relative imports to bring in dependencies from other modules.
4. Add named exports via `__all__` if needed.
5. Write a corresponding test file following the `*.test.*` pattern.
6. Commit your changes with a clear, concise message.

### Writing and Running Tests
**Trigger:** When you need to test new or existing functionality  
**Command:** `/run-tests`

1. Create a test file with `.test.` in its name (e.g., `featureModule.test.py`).
2. Write test functions for your module.
3. Use the project's preferred test runner (framework unknown; check project docs or use `pytest` as default).
4. Run tests and ensure all pass before committing.

## Testing Patterns

- **Test File Naming:**  
  Test files follow the `*.test.*` pattern.  
  Example: `userManager.test.py`
- **Framework:**  
  Not explicitly specified. Use standard Python test frameworks like `unittest` or `pytest` if unsure.
- **Test Location:**  
  Place test files alongside the modules they test or in a dedicated `tests` directory.

## Commands
| Command       | Purpose                                   |
|---------------|-------------------------------------------|
| /add-module   | Scaffold and add a new module             |
| /run-tests    | Run all tests in the codebase             |
```