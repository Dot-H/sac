# sac

Project aiming to implement an Edit and Continue module for gdb.

## Warranty

This project is just a funny thing coded when being bored.
Even if the main features work, the project is not actively maintained
and a lot of things are yet to do. Even if not yet spotted, bug can
occur, making the process segfault.

## Utility

Sac allows a debugged binary to be updated with the changes made
in source files.

Changes can be of the following types:
* Adding functions
* Removing functions
* Adding code in functions
* Removing code from functions
* Modifying value of global variables

The constraints are:
* Type of global variables cannot be modified
* Changes applied to a function will be applied only when
  ENTERING the function.

## Installation

./PATH/TO/SAC/install.sh [GDBINIT_FILE]

## Usage

(gdb) sac --build-file build.sac # load an optional .sac
(gdb) sac file.c ... # Edit the code from the files given in argument

## Authors

Alexandre 'Dot-H' Bernard (alexandre.bernard@lse.epita.fr)
