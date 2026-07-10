```markdown
# slipstream Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `slipstream` Python codebase. It covers file organization, import/export styles, commit message habits, and testing patterns. By following these guidelines, contributors can write code that is consistent, maintainable, and easy to integrate with the rest of the project.

## Coding Conventions

### File Naming
- Use **camelCase** for all file names.
  - **Example:** `dataProcessor.py`, `userManager.py`

### Import Style
- Use **relative imports** within the package.
  - **Example:**
    ```python
    from .utils import parseConfig
    from .models import User
    ```

### Export Style
- Use **named exports** (explicitly define what is exported from a module).
  - **Example:**
    ```python
    __all__ = ['User', 'parseConfig']
    ```

### Commit Patterns
- Commit messages are **freeform**, with no enforced prefix.
- Average commit message length is about 28 characters.
  - **Example:**  
    ```
    fix user loading bug
    add config parser
    ```

## Workflows

### Adding a New Module
**Trigger:** When you need to add a new feature or component.
**Command:** `/add-module`

1. Create a new file using camelCase (e.g., `featureHandler.py`).
2. Use relative imports to bring in dependencies from the package.
3. Define `__all__` to specify named exports.
4. Write or update tests in a corresponding `*.test.*` file.
5. Commit changes with a concise, descriptive message.

### Running Tests
**Trigger:** When you want to verify code correctness.
**Command:** `/run-tests`

1. Locate all test files matching the `*.test.*` pattern.
2. Use the project's preferred (unknown) test runner to execute tests.
3. Review output and address any failures.

### Refactoring Code
**Trigger:** When improving or restructuring existing code.
**Command:** `/refactor`

1. Update file names to camelCase if necessary.
2. Ensure all imports are relative.
3. Update `__all__` in each module to reflect current exports.
4. Run all tests to confirm nothing is broken.
5. Commit with a clear message describing the refactor.

## Testing Patterns

- Test files follow the `*.test.*` naming pattern (e.g., `userManager.test.py`).
- The specific testing framework is not detected; use the project's standard runner.
- Place tests alongside or near the code they validate.
- Example test file:
  ```python
  # userManager.test.py
  from .userManager import User

  def test_user_creation():
      user = User("Alice")
      assert user.name == "Alice"
  ```

## Commands
| Command        | Purpose                                      |
|----------------|----------------------------------------------|
| /add-module    | Scaffold a new module with conventions       |
| /run-tests     | Run all tests in the codebase                |
| /refactor      | Refactor code to follow project conventions  |
```
