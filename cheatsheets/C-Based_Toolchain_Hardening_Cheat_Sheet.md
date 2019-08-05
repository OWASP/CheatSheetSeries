# Introduction

**C-Based Toolchain Hardening Cheat Sheet** is a brief treatment of project settings that will help you deliver reliable and secure code when using C, C++ and Objective C languages in a number of development environments. A more in-depth treatment of this topic can be found [here](C-Based_Toolchain_Hardening.md). This cheatsheet will guide you through the steps you should take to create executables with firmer defensive postures and increased integration with the available platform security. Effectively configuring the toolchain also means your project will enjoy a number of benefits during development, including enhanced warnings and static analysis, and self-debugging code.

There are four areas to be examined when hardening the toolchain: configuration, integration, static analysis, and platform security. Nearly all areas are overlooked or neglected when setting up a project. The neglect appears to be pandemic, and it applies to nearly all projects including Auto-configured projects, Makefile-based, Eclipse-based, and Xcode-based. It's important to address the gaps at configuration and build time because it's difficult to impossible to [add hardening on a distributed executable after the fact](http://sourceware.org/ml/binutils/2012-03/msg00309.html) on some platforms.

For those who would like a deeper treatment of the subject matter, please visit [C-Based Toolchain Hardening](C-Based_Toolchain_Hardening.md).

# Actionable Items

The C-Based Toolchain Hardening Cheat Sheet calls for the following actionable items:

- Provide debug, release, and test configurations
- Provide an assert with useful behavior
- Configure code to take advantage of configurations
- Properly integrate third party libraries
- Use the compiler's built-in static analysis capabilities
- Integrate with platform security measures

The remainder of this cheat sheet briefly explains the bulleted, actionable items. For a thorough treatment, please visit the [full article](C-Based_Toolchain_Hardening.md).

# Build Configurations

You should support three build configurations. First is *Debug*, second is *Release*, and third is *Test*. One size does **not** fit all, and each speaks to a different facet of the engineering process. You will use a debug build while developing, your continuous integration or build server will use test configurations, and you will ship release builds.

1970's K&R code and one size fits all flags are from a bygone era. Processes have evolved and matured to meet the challenges of a modern landscape, including threats. Because tools like Autconfig and Automake [do not support the notion of build configurations](https://lists.gnu.org/archive/html/automake/2012-12/msg00019.html), you should prefer to work in an Integrated Develop Environments (IDE) or write your makefiles so the desired targets are supported. In addition, Autconfig and Automake often ignore user supplied flags (it depends on the folks writing the various scripts and templates), so you might find it easier to again write a makefile from scratch rather than retrofitting existing auto tool files.

## Debug Builds

Debug is used during development, and the build assists you in finding problems in the code. During this phase, you develop your program and test integration with third party libraries you program depends upon. To help with debugging and diagnostics, you should define `DEBUG` and `_DEBUG` (if on a Windows platform) preprocessor macros and supply other 'debugging and diagnostic' oriented flags to the compiler and linker. Additional preprocessor macros for selected libraries are offered in the [full article](C-Based_Toolchain_Hardening.md).

You should use the following for GCC when building for debug: `-O0` (or `-O1`) and `-g3` `-ggdb`. No optimizations improve debuggability because optimizations often rearrange statements to improve instruction scheduling and remove unneeded code. You may need `-O1` to ensure some analysis is performed. `-g3` ensures maximum debug information is available, including symbolic constants and `#defines`.

Asserts will help you write self debugging programs. The program will alert you to the point of first failure quickly and easily. Because asserts are so powerful, the code should be completely and full instrumented with asserts that: (1) validates and asserts all program state relevant to a function or a method; (2) validates and asserts all function parameters; and (3) validates and asserts all return values for functions or methods which return a value. Because of item (3), you should be very suspicious of void functions that cannot convey failures.

Anywhere you have an `if` statement for validation, you should have an assert. Anywhere you have an assert, you should have an `if` statement. They go hand-in-hand. Posix states if `NDEBUG` is **not** defined, then `assert` ["shall write information about the particular call that failed on stderr and shall call abort"](http://pubs.opengroup.org/onlinepubs/009604499/functions/assert.html). Calling abort during development is useless behavior, so you must supply your own assert that `SIGTRAP`s. A Unix and Linux example of a `SIGTRAP` based assert is provided in the [full article](C-Based_Toolchain_Hardening.md).

Unlike other debugging and diagnostic methods - such as breakpoints and `printf` - asserts stay in forever and become silent guardians. If you accidentally nudge something in an apparently unrelated code path, the assert will snap the debugger for you. The enduring coverage means debug code - with its additional diagnostics and instrumentation - is more highly valued than unadorned release code. If code is checked in that does not have the additional debugging and diagnostics, including full assertions, you should reject the check-in.

## Release Builds

Release builds are diametrically opposed to debug configurations. In a release configuration, the program will be built for use in production. Your program is expected to operate correctly, securely and efficiently. The time for debugging and diagnostics is over, and your program will define `NDEBUG` to remove the supplemental information and behavior.

A release configuration should also use `-O2`/`-O3`/`-Os` and `-g1`/`-g2`. The optimizations will make it somewhat more difficult to make sense of a stack trace, but they should be few and far between. The `-g`*`N`* flag ensures debugging information is available for post mortem analysis. While you generate debugging information for release builds, you should strip the information before shipping and check the symbols into you version control system along with the tagged build.

Release builds should also consider the configuration pair of `-mfunction-return=thunk` and `-mindirect-branch=thunk`. These are the "Reptoline" fix which is an indirect branch used to thwart speculative execution CPU vulnerabilities such as Spectre and Meltdown. The CPU cannot tell what code to \[speculatively\] execute because it is an indirect (as opposed to a direct) branch. This is an extra layer of indirection, like calling a pointer through a pointer.

`NDEBUG` will also remove asserts from your program by defining them to `void` since its not acceptable to crash via `abort` in production. You should not depend upon assert for crash report generation because those reports could contain sensitive information and may end up on foreign systems, including for example, [Windows Error Reporting](http://msdn.microsoft.com/en-us/library/windows/hardware/gg487440.aspx). If you want a crash dump, you should generate it yourself in a controlled manner while ensuring no sensitive information is written or leaked.

Release builds should also curtail logging. If you followed earlier guidance, you have properly instrumented code and can determine the point of first failure quickly and easily. Simply log the failure and and relevant parameters. Remove all `NSLog` and similar calls because sensitive information might be logged to a system logger. Worse, the data in the logs might be egressed by backup or sync. If your default configuration includes a logging level of ten or *maximum verbosity*, you probably lack stability and are trying to track problems in the field. That usually means your program or library is not ready for production.

## Test Builds

A Test build is closely related to a release build. In this build configuration, you want to be as close to production as possible, so you should be using `-O2`/`-O3`/`-Os` `-g1`/`-g2` and "Reptoline" configuration options. You will run your suite of *positive* and *negative* tests against the test build.

You will also want to exercise all functions or methods provided by the program and not just the public interfaces, so everything should be made public. For example, all member functions public (C++ classes), all selectors (Objective C), all methods (Java), and all interfaces (library or shared object) should be made available for testing. As such, you should:

- Add `-Dprotected=public` `-Dprivate=public` to `CFLAGS` and `CXXFLAGS`
- Change `__attribute__` `((visibility` `("hidden")))` to `__attribute__` `((visibility` `("default")))`

Many Object Oriented purist oppose testing private interfaces, but this is not about object oriented-ness. This (*q.v.*) is about building reliable and secure software.

You should also concentrate on negative tests. Positive self tests are relatively useless except for functional and regression tests. Since this is your line of business or area of expertise, you should have the business logic correct when operating in a benign environment. A hostile or toxic environment is much more interesting, and that's where you want to know how your library or program will fail in the field when under attack.

# Library Integration

You must properly integrate and utilize libraries in your program. Proper integration includes acceptance testing, configuring for your build system, identifying libraries you *should* be using, and correctly using the libraries. A well integrated library can compliment your code, and a poorly written library can detract from your program. Because a stable library with required functionality can be elusive and its tricky to integrate libraries, you should try to minimize dependencies and avoid third party libraries whenever possible.

Acceptance testing a library is practically non-existent. The testing can be a simple code review or can include additional measures, such as negative self tests. If the library is defective or does not meet standards, you must fix it or reject the library. An example of lack of acceptance testing is [Adobe's inclusion of a defective Sablotron library](http://www.agarri.fr/blog/index.html), which resulted in [CVE-2012-1525](http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-1525). Another example is the 10's to 100's of millions of vulnerable embedded devices due to defects in `libupnp`. While its popular to lay blame on others, the bottom line is you chose the library so you are responsible for it.

You must also ensure the library is integrated into your build process. For example, the OpenSSL library should be configured **without** SSLv2, SSLv3 and compression since they are defective. That means `config` should be executed with `-no-comp` `-no-sslv2` and `-no-sslv3`. As an additional example, using STLPort your debug configuration should also define `_STLP_DEBUG=1`, `_STLP_USE_DEBUG_LIB=1`, `_STLP_DEBUG_ALLOC=1`, `_STLP_DEBUG_UNINITIALIZED=1` because the library offers the additional diagnostics during development.

Debug builds also present an opportunity to use additional libraries to help locate problems in the code. For example, you should be using a memory checker such as *Debug Malloc Library (Dmalloc)* during development. If you are not using Dmalloc, then ensure you have an equivalent checker, such as GCC 4.8's `-fsanitize=memory`. This is one area where one size clearly does not fit all.

Using a library properly is always difficult, especially when there is no documentation. Review any hardening documents available for the library, and be sure to visit the library's documentation to ensure proper API usage. If required, you might have to review code or step library code under the debugger to ensure there are no bugs or undocumented features.

# Static Analysis

Compiler writers do a fantastic job of generating object code from source code. The process creates a lot of additional information useful in analyzing code. Compilers use the analysis to offer programmers warnings to help detect problems in their code, but the catch is you have to ask for them. After you ask for them, you should take time to understand what the underlying issue is when a statement is flagged. For example, compilers will warn you when comparing a signed integer to an unsigned integer because `-1` `>` `1` after C/C++ promotion. At other times, you will need to back off some warnings to help separate the wheat from the chaff. For example, interface programming is a popular C++ paradigm, so `-Wno-unused-parameter` will probably be helpful with C++ code.

You should consider a clean compile as a security gate. If you find its painful to turn warnings on, then you have likely been overlooking some of the finer points in the details. In addition, you should strive for multiple compilers and platforms support since each has its own personality (and interpretation of the C/C++ standards). By the time your core modules clean compile under Clang, GCC, ICC, and Visual Studio on the Linux and Windows platforms, your code will have many stability obstacles removed.

When compiling programs with GCC, you should use the following flags to help detect errors in your programs. The options should be added to `CFLAGS` for a program with C source files, and `CXXFLAGS` for a program with C++ source files. Objective C developers should add their warnings to `CFLAGS`: `-Wall` `-Wextra` `-Wconversion` `(or` `-Wsign-conversion),` `-Wcast-align,` `-Wformat=2` `-Wformat-security,` `-fno-common,` `-Wmissing-prototypes,` `-Wmissing-declarations,` `-Wstrict-prototypes,` `-Wstrict-overflow,` `and` `-Wtrampolines`. C++ presents additional opportunities under GCC, and the flags include `-Woverloaded-virtual,` `-Wreorder,` `-Wsign-promo,` `-Wnon-virtual-dtor` and possibly `-Weffc++`. Finally, Objective C should include `-Wstrict-selector-match` and `-Wundeclared-selector`.

For a Microsoft platform, you should use: `/W4`, `/Wall`, and `/analyze`. If you don't use `/Wall`, Microsoft recomends using `/W4` and enabling C4191, C4242, C4263, C4264, C4265, C4266, C4302, C4826, C4905, C4906, and C4928. Finally, `/analyze` is Enterprise Code Analysis, which is freely available with the [Windows SDK for Windows Server 2008 and .NET Framework 3.5 SDK](https://www.microsoft.com/en-us/download/details.aspx?id=21) (you don't need Visual Studio Enterprise edition).

For additional details on the GCC and Windows options and flags, see *[GCC Options to Request or Suppress Warnings](http://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html)*, *[“Off By Default” Compiler Warnings in Visual C++](http://blogs.msdn.com/b/vcblog/archive/2010/12/14/off-by-default-compiler-warnings-in-visual-c.aspx)*, and *[Protecting Your Code with Visual C++ Defenses](http://msdn.microsoft.com/en-us/magazine/cc337897.aspx)*.

# Platform Security

Integrating with platform security is essential to a defensive posture. Platform security will be your safety umbrella if someone discovers a bug with security implications - and you should always have it with you. For example, if your parser fails, then no-execute stacks and heaps can turn a 0-day into an annoying crash. Not integrating often leaves your users and customers vulnerable to malicious code. While you may not be familiar with some of the flags, you are probably familiar with the effects of omitting them. For example, Android's Gingerbreak overwrote the Global Offset Table (GOT) in the ELF headers, and could have been avoided with `-z,relro`.

When integrating with platform security on a Linux host, you should use the following flags: `-fPIE` (compiler) and `-pie` (linker), -fstack-protector-all (or -fstack-protector), `-z,noexecstack`, `-z,now`, `-z,relro`. If available, you should also use `_FORTIFY_SOURCES=2` (or `_FORTIFY_SOURCES=1` on Android 4.2), `-fsanitize=address` and `-fsanitize=thread` (the last two should be used in debug configurations). `-z,nodlopen` and `-z,nodump` might help in reducing an attacker's ability to load and manipulate a shared object. On Gentoo and other systems with no-exec heaps, you should also use `-z,noexecheap`.

Windows programs should include `/dynamicbase`, `/NXCOMPAT`, `/GS`, and `/SafeSEH` to ensure address space layout randomizations (ASLR), data execution prevention (DEP), use of stack cookies, and thwart exception handler overwrites.

For additional details on the GCC and Windows options and flags, see *[GCC Options Summary](http://gcc.gnu.org/onlinedocs/gcc/Option-Summary.html)* and *[Protecting Your Code with Visual C++ Defenses](http://msdn.microsoft.com/en-us/magazine/cc337897.aspx)*.