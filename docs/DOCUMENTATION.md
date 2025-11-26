# API Documentation Guide

This guide explains how to document Remill code for API documentation generation.

## Doxygen Comment Style

When contributing to Remill, please add Doxygen comments to public APIs using Javadoc-style:

```cpp
/**
 * @brief Short description (one line)
 * 
 * Longer description with more details.
 * Can span multiple lines.
 * 
 * @param name Parameter description
 * @return Return value description
 * @throws ExceptionType When this exception is thrown
 * @see RelatedFunction
 * @note Important notes
 * @warning Warnings about usage
 */
```

### Common Doxygen Tags

- `@brief` - Short description
- `@param` - Parameter description
- `@return` - Return value description
- `@throws` - Exception information
- `@see` - Cross-references
- `@note` - Additional notes
- `@warning` - Important warnings
- `@deprecated` - Deprecated functionality
- `@example` - Usage examples

### Example

```cpp
/**
 * @brief Decode a single instruction from bytes
 *
 * This function decodes a machine code instruction from the provided
 * byte buffer and populates the Instruction object.
 *
 * @param address The virtual address of the instruction
 * @param bytes Pointer to the instruction bytes
 * @param inst Output parameter for the decoded instruction
 * @return true if decoding was successful, false otherwise
 */
bool DecodeInstruction(uint64_t address, const uint8_t *bytes,
                       Instruction &inst);
```

## Resources

- [Doxygen Manual](https://www.doxygen.nl/manual/)
- [Doxygen Special Commands](https://www.doxygen.nl/manual/commands.html)
