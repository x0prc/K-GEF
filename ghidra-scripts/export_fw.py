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
