// odbg_decompile.java - Ghidra headless post-script (Java; Ghidra 12 dropped
// Jython for PyGhidra, so a Java GhidraScript is the dependency-free choice).
//
// Driven by pyplugins/decompile.py: decompiles the function containing a target
// RVA and writes its pseudo-C to a file the plugin reads back.
//
// args: <rva_hex> <output_file>
// @category odbg

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.FileWriter;
import java.io.PrintWriter;

public class odbg_decompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("odbg_decompile: expected <rva_hex> <output_file>");
            return;
        }
        String rvaStr = args[0].startsWith("0x") || args[0].startsWith("0X")
                ? args[0].substring(2) : args[0];
        long rva = Long.parseLong(rvaStr, 16);
        String outpath = args[1];

        Address target = currentProgram.getImageBase().add(rva);
        Function func = getFunctionContaining(target);

        PrintWriter w = new PrintWriter(new FileWriter(outpath));
        try {
            if (func == null) {
                w.println("// no function contains RVA 0x" + Long.toHexString(rva)
                          + " (target " + target + ")");
                return;
            }
            DecompInterface di = new DecompInterface();
            di.openProgram(currentProgram);
            DecompileResults res = di.decompileFunction(func, 60, monitor);
            if (res != null && res.decompileCompleted()) {
                w.print(res.getDecompiledFunction().getC());
            } else {
                w.println("// decompile failed for " + func.getName() + ": "
                          + (res != null ? res.getErrorMessage() : "no result"));
            }
        } finally {
            w.close();
        }
    }
}
