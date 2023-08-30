## Windows: Using the loader to load sys or dll from memory

### PE2Header

-   PE2Header: Read the PE file and generate a header file, Every byte will XOR MAGIC `0x35`
-   PS: use MFC

### load dll from memory

-   platform:x86/x64

-   TestDll: A simple DLL that call OutputDebugString every 1 second
-   TestApp: Example of a DLL loader
-   PS: only scratch free loading of DLLs in the Loader process space,Traceless injection into other process spaces temporarily unavailable

### load sys from memory

-   platform:x64

-   TestDriver: A simple Driver that call OutputDebugString every 1 second
-   DriverLoader: Example of a Driver loader

### usage

#### load dll

-   step1: compile PE2Header project --> PE2Header\x64\Release\PE2Header.exe
-   step2: compile TestDll project --> TestDll\Release\TestDll.dll
-   step3: open PE2Header.exe and choose TestDll.dll --> TestDll\Release\pee.h
-   step4: add TestDll\Release\pee.h to TestApp, then run it......

#### load sys

-   step1: compile PE2Header project --> PE2Header\x64\Release\PE2Header.exe
-   step2: compile TestDriver project --> TestDriver\x64\Debug\TestDriver.sys
-   step3: open PE2Header.exe and choose TestDriver.sys --> TestDriver\x64\Debug\pee.h
-   step4: add TestDriver\x64\Debug\pee.h to DriverLoader, then compile --> DriverLoader\x64\Debug\DriverLoader.sys
-   step5: Using the driver loading tool to load DriverLoader.sys
