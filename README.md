# CyoEncrypt.NET

CyoEncrypt.NET is an easy-to-use command-line file encryptor.

## Features

- Written in .NET 5.0
- CyoEncrypt can encrypt (and decrypt) a single file
- Files are encrypted using AES
- Encrypted files are identified with an extension of ".encrypted"

## Setup

### Windows

Download and install the .NET 5.0 SDK: https://dotnet.microsoft.com/download

Now execute:

    cd src
    test.bat
    publish.bat

Copy the contents of the *pub* subfolder to a folder that's accessible to your PATH.

### Linux

Install the .NET 5.0 SDK, by following the instructions for your distribution: https://docs.microsoft.com/en-us/dotnet/core/install/linux

If your package manager doesn't include it, the .NET SDK can be installed via Snap: https://snapcraft.io/dotnet-sdk

Add this line to $HOME/.profile or $HOME/.bashrc:

    export DOTNET_ROOT=/var/lib/snapd/snap/dotnet-sdk/current

Logout, then log back in.

Now setup CyoEncrypt using:

    cd src
    ./test.sh
    ./publish.sh

    mkdir $HOME/bin
    cp pub/* $HOME/bin
    cd $HOME/bin
    ln -s CyoEncrypt cyoencrypt
    ln -s CyoEncrypt ce

The symbolic links are optional but recommended. Ensure $HOME/bin is in the PATH; this might already be configured in $HOME/.profile or $HOME/.bashrc.

## Usage

Encrypt or decrypt a single file:

    cyoencrypt pathname [password] [--no-confirm]

Encrypt or decrypt the files within a folder:

    cyoencrypt path [password] [--no-confirm] [-r|--recurse] [--exclude=folder,...]

If the password isn't passed on the command line, then the user is prompted to type it.

If --no-confirm is specified, then the user isn't prompted to confirm the password.

When specifying a folder, certain subfolders can be excluded via the --exclude argument, for example:

    --exclude=obj,node_modules

## To Do

- Securely overwrite original plaintext file once encrypted
- Ability to easily manually re-encrypt a file
- Ability to automatically re-encrypt a file after an idle period

## Licence

The MIT License (MIT)

Copyright (c) 2020-2021 Graham Bull

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
