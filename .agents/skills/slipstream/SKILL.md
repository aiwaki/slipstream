```markdown
# slipstream Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the core development patterns and conventions used in the `slipstream` Python codebase. You'll learn about file organization, import/export styles, commit message conventions, and how to structure and run tests. These patterns help maintain consistency and readability across the project.

## Coding Conventions

### File Naming
- Use **snake_case** for all file names.
  - Example: `data_processor.py`, `user_manager.py`

### Import Style
- Use **relative imports** within the package.
  - Example:
    ```python
    from .utils import parse_config
    ```

### Export Style
- Use **named exports**; explicitly specify what is exported from each module.
  - Example:
    ```python
    __all__ = ['MyClass', 'my_function']
    ```

### Commit Messages
- Follow **conventional commit** patterns.
- Use prefixes such as `test`.
- Keep commit messages concise (average 48 characters).
  - Example:
    ```
    test: add unit tests for data parser
    ```

## Workflows

### Adding a New Module
**Trigger:** When you need to add new functionality to the codebase.
**Command:** `/add-module`

1. Create a new Python file using snake_case (e.g., `new_feature.py`).
2. Implement your functionality.
3. Use relative imports to reference other modules.
4. Specify named exports with `__all__`.
5. Write corresponding tests in a `*.test.*` file.

### Writing and Running Tests
**Trigger:** When you add or update code and need to verify correctness.
**Command:** `/run-tests`

1. Create a test file following the pattern `*.test.*` (e.g., `utils.test.py`).
2. Write test functions for your code.
3. Use the project's preferred testing framework (framework is currently unknown; check existing test files for clues).
4. Run the tests using the appropriate command or tool.

### Committing Changes
**Trigger:** When you are ready to save your changes to version control.
**Command:** `/commit-changes`

1. Write a commit message using the conventional commit format.
   - Prefix with the type (e.g., `test:`).
   - Keep the message concise and descriptive.
2. Commit your changes.

## Testing Patterns

- Test files follow the pattern `*.test.*` (e.g., `module.test.py`).
- The specific testing framework is unknown; inspect existing test files for framework clues.
- Place tests alongside or near the modules they test.
- Example test file structure:
  ```python
  def test_parse_config():
      assert parse_config("key=value") == {"key": "value"}
  ```

## Commands
| Command        | Purpose                                      |
|----------------|----------------------------------------------|
| /add-module    | Scaffold and add a new module                |
| /run-tests     | Run all test files in the codebase           |
| /commit-changes| Commit changes using conventional commit style|
```
