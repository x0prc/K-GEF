from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SourceType
import json

def export_analysis(program):
    results = {
        "functions": [],
        "calls": [],
        "strings": [],
        "imports": []
    }
    # Export Functions
    for func in program.getFunctionManager().getFunctions(True);
        results["functions"].append({
            "addr": hex(func.getEntryPoint().getOffset()),
            "name": func.getName(),
            "size": func.getBody().getNumAddresses()
        })

    # Export Caller -> Callee 
    for func in program.getFunctionManager().getFunctions(True):
        caller_addr = func.getEntryPoint().getOffset()
        for dest in func.getCallDestinations():
            results["calls"].append({
                "caller": hex(caller_addr),
                "callee": hex(dest.getDestinationAddress().getOffset())
            })

    # Export strings + xrefs
    for str_obj in program.getListing().getDefinedData(True):
        if str_obj.getValue() and isinstance(str_obj.getValue(), unicode):
            str_data = {
                "addr": hex(str_obj.getAddress().getOffset()),
                "value": str_obj.getValue().toString()
            }
            results["strings"].append(str_data)

    # Export Imports
    for sym in program.getSymbolTable().getExternalSymbols():
        results["imports"].append({
            "name": sym.getName(),
            "addr": hex(sym.getAddress().getOffset())
        })

    return results 

    if __name__ == '__main__':
        analysis = export_analysis(currentProgram)
        print(json.dumps(analysis, indent=2))
