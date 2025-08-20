# Disable Java Bytecode Verification at Runtime

> **⚠WARNING**: Disabling bytecode verification introduces significant security vulnerabilities and can lead to JVM instability.

## Build 

```bash
$ gcc -s -shared -o disabler.dll disabler.c
```

## Usage

To utilize this library, load the compiled native library within your Java application wherever you want.

```java
static {
    System.loadLibrary("disabler");
}
```

Then the Bytecode Verification should be disabled.

## Compatibility

The current implementation is primarily targeted for the Windows operating system. However, the underlying logic is not complex and can be ported to other operating systems (such as Linux or macOS) with minor modifications.

## Acknowledgments

This project is inspired with [noverify-hackery](https://github.com/char/noverify-hackery)
