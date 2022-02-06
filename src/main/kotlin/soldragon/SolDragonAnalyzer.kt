package soldragon

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.LongDataType
import ghidra.program.model.data.Pointer64DataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Function.FunctionUpdateType
import ghidra.program.model.listing.Parameter
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import java.util.function.Consumer


class SolDragonAnalyzer : AbstractAnalyzer(
    "Solana Analyzer", "Analyzer fixes entrypoint signature", AnalyzerType.FUNCTION_SIGNATURES_ANALYZER
) {
    override fun getDefaultEnablement(program: Program): Boolean {
        return program.language.processor.toString() == "solBPF"
    }

    override fun canAnalyze(program: Program): Boolean {
        return program.language.processor.toString() == "solBPF"
    }

    override fun registerOptions(options: Options?, program: Program?) {}

    @Throws(CancelledException::class)
    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {

        //TODO don't run this on every set or so
        program.symbolTable.getSymbols("entrypoint").forEach(Consumer { sym: Symbol ->
            val f: Function = program.functionManager.getFunctionAt(sym.address)
            val returnParam: Parameter =
                ParameterImpl("output", LongDataType(), program.getRegister("R0"), program)
            val p1: Parameter =
                ParameterImpl("input", Pointer64DataType(CharDataType()), program.getRegister("R1"), program)
            f.updateFunction(
                "bpf_call", returnParam, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS, p1
            )
        })
        return true
    }
}