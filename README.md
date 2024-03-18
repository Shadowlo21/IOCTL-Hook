# IOCTL Driver for Memory Manipulation

This is an IOCTL (Input/Output Control) driver designed for memory manipulation tasks. It provides various functionalities such as writing to memory, reading from memory, allocating and freeing memory, protecting memory, and obtaining base addresses.

## Features

### Write Memory

Write data to a specific memory address.

### Read Memory

Read data from a specific memory address.

### Free Memory

Free previously allocated memory.

### Allocate Memory

Allocate a block of memory with specified size.

### Protect Memory

Change protection settings for a memory region.

### Get Base Address

Retrieve the base address of a specified module.

## Usage

1. Start the vulnerable driver using the "sc" command.
2. Load the main driver using kdmapper.
3. Utilize the provided commands to perform memory manipulation tasks.

## Compatibility

This driver is compatible with FaceInjector. You can embed the driver in this injector with the following link

[face-injector-v2](https://github.com/KANKOSHEV/face-injector-v2). [ Will Need Sum Recoding ]



Additionally, it is compatible with IanInject. You can embed the driver in this injector with the following link

[CodMWKernelInjector](https://github.com/glitteru/CodMWKernelInjector). [ %100 Compatible ]

## Disclaimer

This driver is for educational purposes only. Improper use may lead to system instability or security risks. Use at your own risk.

## Contributing

Contributions are welcome! If you have any ideas for new features, improvements, or bug fixes, feel free to open an issue or submit a pull request.
