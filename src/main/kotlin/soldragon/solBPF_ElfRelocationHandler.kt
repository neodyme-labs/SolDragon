package soldragon

import ghidra.app.util.bin.format.elf.ElfConstants
import ghidra.app.util.bin.format.elf.ElfHeader
import ghidra.app.util.bin.format.elf.ElfRelocation
import ghidra.app.util.bin.format.elf.ElfSymbol
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationHandler
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.address.Address
import ghidra.program.model.mem.Memory
import ghidra.program.model.mem.MemoryAccessException
import ghidra.util.exception.NotFoundException


class solBPF_ElfRelocationHandler : ElfRelocationHandler() {
    override fun canRelocate(elf: ElfHeader): Boolean {
        return elf.e_machine() == ElfConstants.EM_BPF
    }

    @Throws(MemoryAccessException::class, NotFoundException::class)
    override fun relocate(
        elfRelocationContext: ElfRelocationContext, relocation: ElfRelocation, relocationAddress: Address
    ) {
        val elf = elfRelocationContext.elfHeader
        if (!canRelocate(elf)) {
            return
        }
        val program = elfRelocationContext.program
        val memory: Memory = program.memory
        val symbolIndex = relocation.symbolIndex
        var sym: ElfSymbol? = null
        var symbolValue: Long = 0
        var symbolName: String? = null
        if (symbolIndex != 0) {
            sym = elfRelocationContext.getSymbol(symbolIndex)
        }
        if (null != sym) {
            symbolValue = elfRelocationContext.getSymbolValue(sym)
            symbolName = sym.nameAsString
        }

        when (relocation.type) {
            BPF_NONE -> {}
            BPF_64_RELATIVE -> {
                //we use relative addressing in sleigh definitions, so this should be fine?
            }
            BPF_64_32 -> if (sym != null && sym.isFunction && symbolValue != 0L) {
                memory.setInt(
                    relocationAddress.add(4), (symbolValue - relocationAddress.add(8).offset shr 3).toInt()
                )
                println("bpfCall $symbolName")
            } else {
                var v: Int = memory.getInt(relocationAddress)
                v = v or 240 //arith opc syscall
                memory.setInt(relocationAddress, v)


                //TODO: make this clean, maybe hook loader?
                if (memory.getBlock("syscall") == null) {
                    val addr: Address = program.addressFactory.getAddressSpace("syscall").getAddress(0)
                    memory.createUninitializedBlock("syscall", addr, 0x100, false)
                }
                if (!SYSCALLS.contains(symbolName)) {
                    println("syscall $symbolName")
                    SYSCALLS.add(symbolName)
                }
                val idx = SYSCALLS.indexOf(symbolName)
                memory.setInt(relocationAddress.add(4), idx)
                val addr: Address = program.addressFactory.getAddressSpace("syscall").getAddress(idx.toLong())
                val api = FlatProgramAPI(program)
                api.createFunction(addr, symbolName)
            }
            else -> throw Exception(String.format("Relocation Type %d is unimplemented", relocation.type))
        }

    }

    companion object {
        private val SYSCALLS = ArrayList<String?>()
        const val BPF_NONE = 0
        const val BPF_64_64 = 1
        const val BPF_64_RELATIVE = 8
        const val BPF_64_32 = 10
        const val PROGRAM_START = 0x100000000L
        const val STACK_START = 0x200000000L
        const val HEAP_START = 0x300000000L
        const val INPUT_START = 0x400000000L
    }
}
