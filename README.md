# SimpleSvm

SimpleSvm is an educational and research-oriented project designed to help understand how a minimal hypervisor works on Windows on AMD hardware with SVM (Secure Virtual Machine) support.

This repository contains a Windows kernel driver that:

- validates AMD hardware with SVM/NPT support,
- enables `EFER.SVME`,
- prepares a `VMCB` per processor,
- builds a nested paging map (NPT),
- intercepts `#VMEXIT` events,
- and manages host/guest transitions in a controlled test environment.

The main goal is not to provide a production-ready solution, but to serve as a didactic base for studying the AMD SVM interface, x64 architecture, kernel memory management, and system-level virtualization.

## Project purpose

This implementation is a useful reference for learning:

- how a hypervisor is initialized on Windows,
- how a `VMCB` is built,
- how `#VMEXIT` works,
- what role `CPUID`, `MSR`, `GDTR`, and other system structures play,
- how nested paging (NPT) is used,
- and how host/guest transitions are handled in kernel mode.

The project is intended for lab environments, legitimate research, and technical study. It is not recommended for use outside a controlled environment or on systems that are not part of a test setup.

## Allowed use and warnings

This code is distributed for educational and technical research purposes. It is not intended for:

- bypassing protection systems, DRM, or anti-cheat mechanisms,
- tampering with third-party software,
- or performing activities outside an authorized and controlled environment.

It should be used only on hardware and systems where you have explicit permission to experiment.

## Repository architecture

### Main files

- `SimpleSvm/SimpleSvm.cpp`
  - Main driver logic.
  - Contains SVM activation, VMCB preparation, `#VMEXIT` handling, power callbacks, guest setup, and environment cleanup.

- `SimpleSvm/x64.asm`
  - Assembly implementation for the VM startup routine, stack manipulation, and host/guest transitions.

- `SimpleSvm/SimpleSvm.hpp`
  - AMD definitions, VMCB structures, bit masks, segment descriptors, paging structures, and related helper types.

- `SimpleSvm/SimpleSvm.vcxproj`
  - Visual Studio project used to build the driver with the WDK.

- `SimpleSvm.sln`
  - Main solution file for the repository.

- `LICENSE`
  - Project MIT license.

## Requirements

This project is intended for specific Windows environments and requires compatible hardware:

- Windows x64
- AMD CPU with SVM support
- Support for Nested Page Tables (NPT)
- Windows Driver Kit (WDK)
- Visual Studio with driver development tools
- BIOS/UEFI with SVM enabled
- Kernel debugger or controlled lab environment for low-level testing

## Build instructions

1. Open `SimpleSvm.sln` in Visual Studio.
2. Ensure the correct WDK is installed and configured for your Windows version.
3. Select `x64` and either `Debug` or `Release`.
4. Build the solution.
5. Install or test the driver only in a controlled environment with the required permissions.

> Important: this is not a user-mode project. It is a kernel driver and requires a high level of knowledge of Windows internals, x64, and virtualization.

## How it works internally

### 1. Hardware validation

The driver checks whether the CPU is AMD and whether it supports:

- SVM,
- NPT,
- and whether the system does not prohibit SVM activation.

The verification is performed through `CPUID` and `MSR` reads.

### 2. VMCB preparation

A `VMCB` is created per processor with guest information, including:

- GDT/IDT,
- guest state,
- segment selectors,
- initial `CR0`, `CR3`, and `CR4` values,
- `RSP`, `RIP`, and `RFLAGS` pointers,
- and interception configuration for relevant events.

### 3. Nested paging (NPT)

NPT tables are configured to translate guest physical addresses into host physical addresses using a controlled mapping scheme. This allows the hypervisor to regulate the guest memory view without rewriting the entire host layout.

### 4. `#VMEXIT` handling

When the guest triggers a virtualized-mode exit, execution enters the hypervisor control routine. The code analyzes the reason for the `ExitCode` and decides whether to:

- emulate guest behavior,
- inject an exception,
- modify the `VMCB` state,
- or abort virtualization depending on the case.

Typical exit cases include:

- `CPUID`,
- `MSR` access,
- `GDTR` reads,
- exceptions such as `#DB`, `#PF`, `#AC`, `#SS`,
- and other exits that require host intervention.

### 5. `LSTAR` hook and syscall logic

The project includes logic related to `LSTAR` and manipulation of `KUSER_SHARED_DATA`, using an experimental approach to intercept or redirect certain system paths. This is a representative example of low-level operating system instrumentation in a lab setting.

### 6. Driver lifecycle

The driver registers a power-state callback and performs cleanup when the environment is shutting down or when the driver lifecycle ends. It also manages cleanup paths to avoid memory leaks or inconsistent states.

## Technical structure of the code

### `SimpleSvm.cpp`

This is the central file of the project. It defines:

- driver initialization,
- CPU capability checks,
- VMCB configuration,
- `#VMEXIT` handling,
- guest state manipulation,
- and final environment cleanup.

### `x64.asm`

This contains the low-level assembly used to:

- start the VM,
- prepare the host stack,
- and perform control transfers between host and guest.

### `SimpleSvm.hpp`

This file contains the more complex project definitions:

- paging structures,
- bit masks,
- SVM-related definitions,
- and segment descriptors used during virtualization.

## Limitations

- It is only relevant on AMD systems with SVM/NPT support.
- It is not a normal user-mode application.
- It requires advanced knowledge of kernel mode, x64, Windows internals, and virtualization.
- It should only be tested in isolated environments with proper permissions and supervision.
- It is not intended for production use.

## License

This project uses the MIT license. See `LICENSE` for more details.

## Credits

This repository is based on the technical foundation of Windows driver and virtualization projects and is intended for educational and research purposes. The code is intended for technical study and experimentation in authorized environments.

## Short summary

SimpleSvm is a minimal and educational Windows kernel hypervisor implementation for AMD CPUs. Its focus is the study of the SVM model, VMCB, `#VMEXIT`, nested paging, and the relationship between hardware, the operating system, and virtualization in kernel mode.
