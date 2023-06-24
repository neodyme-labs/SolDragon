# SolDragon

Solana Ghidra Stuff (WIP)

## TODO List:
- [x] SLEIGH Definitions
- [x] fix entrypoint Signature
- [x] stub syscalls
- [ ] fix analysis plugin
- [ ] fix stack frames n SLEIGH definitions?
- [ ] fix syscall name wrong in decompilation
- [ ] make decompilation prettier
- [ ] change memory map to rbpf vm
- [ ] somehow implement solana structures
- [ ] create proper function signatures for syscalls
- [ ] automatically create function id db
- [ ] compiler/sdk detection
- [ ] implement partial emulation for better decompilation

## Building
Set `GHIDRA_INSTALL_DIR` in your home `gradle.properties` or as an environment variable to point to your Ghidra installation.
Run `./gradlew buildExtension` to build the extension.
