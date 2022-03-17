# LibRedFat -- A Hardened Malloc Implementation

LibRedFat is a hardened `malloc`/`free` implementation based on two
complementary memory error detection technologies:

* *Poisoned Redzones*
* *Low-Fat-Pointers*

You can use LibRedFat to harden binaries without the need for
recompilation or instrumentation.

## Building

To build LibRedFat, simply run the script:

        $ ./build.sh

## Usage

To test LibRedFat, simply replace the default `malloc` implementation
using `LD_PRELOAD`, e.g.:

        $ LD_PRELOAD=$PWD/libredfat.so xterm

Alternatively, you can statically link `libredfat.a` into your program.

## Protections

LibRedFat replaces several `libc` functions with hardened versions that
check for memory errors, including:

* `memcpy()`
* `memset()`
* `memcmp()`
* `strcmp()`
* `strcpy()`
* `strlen()`
* `strcat()`
* etc.

Memory errors on heap pointers allocated using LibRedFat will be
automatically detected by these replacement functions.

LibRedFat can be used in conjunction with the
[RedFat](https://github.com/GJDuck/RedFat) binary hardening system.
For this, please see the [RedFat](https://github.com/GJDuck/RedFat)
project for more information.

## Performance

Security and performance are a trade-off, and most existing `malloc`
implementations are optimized for performance.
In contrast, LibRedFat attempts to optimize towards security, provided
that the performance impact is "reasonable".

As such, the runtime performance of LibRedFat should be somewhat similar
to the default `malloc`/`free` implementation for most programs.

The memory performance of LibRedFat should be slightly worse than the
default `malloc`/`free` implementation, mainly because of the use of
*poisoned redzones*, *low-fat pointer* size binning, and a disjoint metadata
for the freelists.
It is recommended to profile each potential use case.

## Options

LibRedFat supports various optional features that can be enabled using
environment variables.
Some features can also be statically enabled using the `build.sh` script (see
`build.sh --help` for more information):

* `REDFAT_PROFILE=1`: Enable profiling information such as the number of
  allocations and total library checks.
  Default: *disabled*.
* `REDFAT_TEST=N`: Enable "test"-mode that randomly (once per `N`
  allocations) under-allocates by a single byte.
  If instrumented code accesses the missing byte then a memory error should
  be detected.
  A zero value disables test-mode.
  Default: 0 (*disabled*).
* `REDFAT_QUARANTINE=N`: Delay re-allocation of objects until `N` bytes have
  been free'ed.
  This can help detect reuse-after-free errors by not immediately
  reallocating objects, at the cost of increased memory overheads.
  However, this can increase memory overheads.
  Note that `N` is a per-*region* value for each allocation size-class, so
  the total overhead could be `N*M` where `M` is the number of regions
  (typically ~60).
  Default: 0.
* `REDFAT_ZERO=1`: Enable the zeroing of objects during deallocation.
  Provides additional defense against *use-after-free* errors and a basic
  defense against *uninitialized-read* errors.
  However, zeroing adds additional performance overheads.
  Default: *disabled*.
* `REDFAT_CANARY=1`: Enables a randomized canary to be placed at the end of
  all allocated objects.
  The canary provides additional protection for out-of-bounds write errors
  that may go undetected in uninstrumented code.
  This consumes an additional 8 bytes per allocation.
  Note that a canary is always placed at the beginning of all allocated
  objects since this does not consume additional space.
  Default: *disabled*.
* `REDFAT_ASLR=1`: Enables *Address Space Layout Randomization* (ASLR) for
  heap allocations.
  Default: *enabled*.

## History

LibRedFat is derived (after heavy modification) from the `liblowfat.so`
library, which is part of the [LowFat](https://github.com/GJDuck/LowFat)
project.
Several new features have been added, including:

* Lock-free (thread-local) allocation
* Redzones
* A disjoint metadata for freelists
* Intercepting (and protecting) several common libc functions (`memcpy`,
  etc.)
* Several additional hardening options (quarantines, zeroing, canaries).
* Improved ASLR.
* Improved virtual address space management.
* Compatible with `LD_PRELOAD`.
* Etc.

LibRedFat was originally developed as part of the
[RedFat](https://github.com/GJDuck/RedFat) project.
However, `libredfat.so` can be used independently of RedFat as a hardened
`malloc` implementation.

LibRedFat is beta quality software, and has not yet been properly tested.
It is possible that there are bugs or security vulnerabilities, so should be
independently accessed before use in production code.
LibRedFat is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.

## Further Reading

* Gregory J. Duck, Yuntong Zhang, Roland H. C. Yap,
  [Hardening Binaries against More Memory Errors](https://www.comp.nus.edu.sg/~gregory/papers/redfat.pdf),
  European Conference on Computer Systems (EuroSys), 2022

## License

This software has been released under the MIT License.

## Acknowledgements

This work was partially supported by the National Satellite of Excellence in
Trustworthy Software Systems, funded by the National Research Foundation (NRF)
Singapore under the National Cybersecurity R&D (NCR) programme.

This work was partially supported by the Ministry of Education, Singapore
(Grant No. MOE2018-T2-1-142).

