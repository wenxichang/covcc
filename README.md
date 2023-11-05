# Covcc
Generate linux kernel module coverage reports without recompiling the kernel.

# Usage

## Compile and install
```shell
# compile
cd src && make

# install
make install

# or install to other path
make PREFIX=/path/to/your/bin install

```

This project contain 2 commands:
* covcc: inject counter and code into the module code and stat the coverage.
* cov_reader: read the counter and generate report, etc.

# Usage of covcc

**Do not need to recompile the kernel or change any kernel config**
**Do not need to change the module code or makefile**

Just use `make CC=covcc` to recompile the module, and everything is ready.

`covcc` use `gcc` as default compiler, `export ORIG_CC=your_cc` before `make` to overide it.
you can also `export COVDEBUG=1` to show more messages.


# Usage of cov_reader

cov_reader is used to obtain coverage date from the kernel.
!!! cov_reader must have `/proc/kcore` and `/proc/kallsyms` available !!!

some example:

```shell
# read coverage of mymodule and generate report for mymodule.c
cov_reader -m mymodule mymodule.c

# read coverage from kernel space and save to file
cov_reader -o mymodule_from_1.data

# collect coverage from another machine
cov_reader -o mymodule_from_2.data

# merge coverage data and generate reports for c sources, output summary.
cov_reader -a -i mymodule_from_1.data -i mymodule_from_2.data /path/to/mysrc/*.c

```

use `--xml` to generate cobertuna reports

have fun.