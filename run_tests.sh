#!/usr/bin/env bash
set -e

# Find FileCheck
FILECHECK=$(which FileCheck || echo "FileCheck")

# Plugin paths
TIDY_PLUGIN="$(pwd)/build/lib/libPostgresTidyModule.dylib"
ANALYZER_PLUGIN_LISTFREE="$(pwd)/build/lib/libListFreeChecker.dylib"
ANALYZER_PLUGIN_PGTRY="$(pwd)/build/lib/libReturnInPgTryBlockChecker.dylib"

echo "Running tests..."

for test_file in test/*.c; do
    echo "Testing $test_file"
    
    # Extract RUN lines
    grep "^// RUN:" "$test_file" | sed 's|^// RUN: ||' | while read -r cmd; do
        # Replace variables
        cmd="${cmd//%tidy_plugin/$TIDY_PLUGIN}"
        cmd="${cmd//%analyzer_plugin_listfree/$ANALYZER_PLUGIN_LISTFREE}"
        cmd="${cmd//%analyzer_plugin_pgtry/$ANALYZER_PLUGIN_PGTRY}"
        
        # If it's a generic %analyzer_plugin, figure out which one based on the file name
        if [[ "$test_file" == *"list_free"* ]]; then
            cmd="${cmd//%analyzer_plugin/$ANALYZER_PLUGIN_LISTFREE}"
        else
            cmd="${cmd//%analyzer_plugin/$ANALYZER_PLUGIN_PGTRY}"
        fi
        
        cmd="${cmd//%s/$test_file}"
        
        # Run the command
        echo "  $cmd"
        eval "$cmd"
    done
done

echo "All tests passed!"
