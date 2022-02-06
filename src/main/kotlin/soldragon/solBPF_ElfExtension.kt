package soldragon

import ghidra.app.util.bin.format.elf.ElfConstants
import ghidra.app.util.bin.format.elf.ElfHeader
import ghidra.app.util.bin.format.elf.ElfLoadHelper
import ghidra.app.util.bin.format.elf.extend.ElfExtension
import ghidra.program.model.lang.Language


class solBPF_ElfExtension : ElfExtension() {
    override fun canHandle(elf: ElfHeader): Boolean {
        return elf.e_machine() == ElfConstants.EM_BPF && elf.is64Bit
    }

    override fun canHandle(elfLoadHelper: ElfLoadHelper): Boolean {
        if (!canHandle(elfLoadHelper.elfHeader)) return false
        val language: Language = elfLoadHelper.program.language
        val size: Int = language.languageDescription.size
        return 64 == size && language.processor.toString() == "solBPF"
    }

    override fun getDataTypeSuffix(): String {
        return "_solBPF"
    }
}
