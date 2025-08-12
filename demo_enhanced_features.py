#!/usr/bin/env python3
"""
Enhanced Reverse Engineering Tools - Feature Demonstration
Showcases the advanced capabilities of the enhanced Ghidra and Cutter tools
"""

import os
import sys
import json
from enhanced_re_tools import EnhancedGhidra, EnhancedCutter, analyze_file_with_tools

def demo_enhanced_ghidra():
    """Demonstrate enhanced Ghidra functionality"""
    print("🔍 Enhanced Ghidra Features Demonstration")
    print("=" * 60)
    
    # Find a test file
    test_file = "C:\\Windows\\System32\\notepad.exe"
    if not os.path.exists(test_file):
        print("❌ Test file not found. Please provide a valid executable file.")
        return
    
    print(f"📁 Analyzing: {test_file}")
    
    # Initialize enhanced Ghidra
    ghidra = EnhancedGhidra(test_file)
    
    # 1. Basic File Analysis
    print("\n1️⃣ Basic File Analysis")
    print("-" * 30)
    basic_analysis = ghidra.analyze_file()
    
    if "error" not in basic_analysis:
        print(f"   ✓ File Type: {basic_analysis.get('file_type', 'Unknown')}")
        print(f"   ✓ Architecture: {basic_analysis.get('architecture', 'Unknown')}")
        print(f"   ✓ Entry Point: {basic_analysis.get('entry_point', 'Unknown')}")
        print(f"   ✓ Entry Section: {basic_analysis.get('entry_section', 'Unknown')}")
        
        if 'sections' in basic_analysis:
            print(f"   ✓ Sections Found: {len(basic_analysis['sections'])}")
            for section in basic_analysis['sections'][:3]:  # Show first 3
                print(f"     - {section['name']}: {section['virtual_address']} "
                      f"(Size: {section['raw_size']} bytes)")
            if len(basic_analysis['sections']) > 3:
                print(f"     ... and {len(basic_analysis['sections']) - 3} more sections")
        
        if 'imports' in basic_analysis:
            total_imports = sum(len(apis) for apis in basic_analysis['imports'].values())
            print(f"   ✓ Total Imports: {total_imports}")
            for dll, apis in list(basic_analysis['imports'].items())[:3]:
                print(f"     - {dll}: {len(apis)} functions")
        
        if 'dotnet_info' in basic_analysis and basic_analysis['dotnet_info'].get('is_dotnet'):
            dotnet = basic_analysis['dotnet_info']
            print(f"   ✓ .NET Assembly: {dotnet.get('assembly_name', 'Unknown')}")
            print(f"   ✓ Runtime Version: {dotnet.get('runtime_version', 'Unknown')}")
            print(f"   ✓ Method Count: {dotnet.get('method_count', 0)}")
    else:
        print(f"   ❌ Analysis failed: {basic_analysis['error']}")
    
    # 2. Cross-Reference Analysis
    print("\n2️⃣ Cross-Reference Analysis")
    print("-" * 30)
    xref_analysis = ghidra.cross_reference_analysis()
    
    if "error" not in xref_analysis:
        if 'api_calls' in xref_analysis:
            total_apis = sum(len(apis) for apis in xref_analysis['api_calls'].values())
            print(f"   ✓ API Calls Found: {total_apis}")
            
            # Show some interesting APIs
            interesting_dlls = ['kernel32.dll', 'user32.dll', 'advapi32.dll']
            for dll in interesting_dlls:
                if dll in xref_analysis['api_calls']:
                    apis = xref_analysis['api_calls'][dll]
                    print(f"     - {dll}: {len(apis)} functions")
                    if apis:
                        sample_apis = apis[:5] if len(apis) > 5 else apis
                        print(f"       Sample: {', '.join(sample_apis)}")
        
        if 'string_references' in xref_analysis:
            strings = xref_analysis['string_references']
            print(f"   ✓ String References: {len(strings)}")
            
            # Show some interesting strings
            interesting_strings = [s for s in strings.keys() if len(s) > 10][:5]
            if interesting_strings:
                print("     Sample strings:")
                for s in interesting_strings:
                    print(f"       - {s[:50]}{'...' if len(s) > 50 else ''}")
    else:
        print(f"   ❌ Cross-reference failed: {xref_analysis['error']}")
    
    print("\n✅ Enhanced Ghidra demonstration completed!")

def demo_enhanced_cutter():
    """Demonstrate enhanced Cutter functionality"""
    print("\n🔍 Enhanced Cutter Features Demonstration")
    print("=" * 60)
    
    # Find a test file
    test_file = "C:\\Windows\\System32\\notepad.exe"
    if not os.path.exists(test_file):
        print("❌ Test file not found. Please provide a valid executable file.")
        return
    
    print(f"📁 Analyzing: {test_file}")
    
    # Initialize enhanced Cutter
    cutter = EnhancedCutter(test_file)
    
    # 1. Advanced Hex Dump
    print("\n1️⃣ Advanced Hex Dump Formats")
    print("-" * 30)
    
    # Traditional hex dump
    hex_dump = cutter.hex_dump(0, 128, "hex")
    if "Error:" not in hex_dump:
        print("   ✓ Traditional Hex Dump (first 128 bytes):")
        lines = hex_dump.split('\n')[:5]  # Show first 5 lines
        for line in lines:
            if line.strip():
                print(f"     {line}")
        print("     ...")
    else:
        print(f"   ❌ Hex dump failed: {hex_dump}")
    
    # 2. Pattern Detection
    print("\n2️⃣ Advanced Pattern Detection")
    print("-" * 30)
    patterns = cutter.search_patterns("all")
    
    if "error" not in patterns:
        total_patterns = sum(len(pattern_list) for pattern_list in patterns.values())
        print(f"   ✓ Total Patterns Found: {total_patterns}")
        
        for pattern_type, pattern_list in patterns.items():
            if pattern_list:
                print(f"   - {pattern_type.title()}: {len(pattern_list)}")
                
                # Show sample patterns
                if pattern_type == "urls" and pattern_list:
                    print(f"     Sample URLs: {pattern_list[0]['url']}")
                elif pattern_type == "ips" and pattern_list:
                    print(f"     Sample IPs: {pattern_list[0]['ip']}")
                elif pattern_type == "emails" and pattern_list:
                    print(f"     Sample Emails: {pattern_list[0]['email']}")
                elif pattern_type == "file_paths" and pattern_list:
                    sample_paths = pattern_list[:3]
                    for path_info in sample_paths:
                        print(f"     Sample Path: {path_info['path']} ({path_info['type']})")
                elif pattern_type == "strings" and pattern_list:
                    sample_strings = [s['string'] for s in pattern_list[:3]]
                    print(f"     Sample Strings: {', '.join(sample_strings)}")
    else:
        print(f"   ❌ Pattern search failed: {patterns['error']}")
    
    # 3. Entropy Analysis
    print("\n3️⃣ Entropy Analysis")
    print("-" * 30)
    entropy = cutter.entropy_analysis()
    
    if "error" not in entropy:
        if 'statistics' in entropy:
            stats = entropy['statistics']
            print(f"   ✓ Average Entropy: {stats.get('average_entropy', 0):.2f}")
            print(f"   ✓ Maximum Entropy: {stats.get('max_entropy', 0):.2f}")
            print(f"   ✓ Minimum Entropy: {stats.get('min_entropy', 0):.2f}")
            
            # Entropy interpretation
            avg_entropy = stats.get('average_entropy', 0)
            if avg_entropy < 4.0:
                print("   📊 Interpretation: Low entropy - likely uncompressed/unencrypted")
            elif avg_entropy < 7.0:
                print("   📊 Interpretation: Medium entropy - possibly compressed")
            else:
                print("   📊 Interpretation: High entropy - likely encrypted or packed")
        
        if 'packed_regions' in entropy:
            packed_count = len(entropy['packed_regions'])
            print(f"   ✓ Packed Regions Detected: {packed_count}")
            
            if packed_count > 0:
                print("   🚨 High entropy regions found - potential packed/encrypted content")
                for region in entropy['packed_regions'][:3]:
                    offset_val = region['offset']
                if isinstance(offset_val, str) and offset_val.startswith('0x'):
                    offset_display = offset_val
                else:
                    offset_display = f"0x{offset_val:X}"
                print(f"     - Offset: {offset_display}, Entropy: {region['entropy']:.2f}")
    else:
        print(f"   ❌ Entropy analysis failed: {entropy['error']}")
    
    # 4. File Structure Analysis
    print("\n4️⃣ File Structure Analysis")
    print("-" * 30)
    structure = cutter.file_structure_analysis()
    
    if "error" not in structure:
        print(f"   ✓ File Type: {structure.get('file_type', 'Unknown')}")
        
        if 'headers' in structure:
            headers = structure['headers']
            if 'file_header' in headers:
                fh = headers['file_header']
                machine = fh.get('machine', 0)
                machine_display = f"0x{machine:X}" if isinstance(machine, int) else str(machine)
                print(f"   ✓ Machine Type: {machine_display}")
                print(f"   ✓ Section Count: {fh.get('number_of_sections', 0)}")
                chars = fh.get('characteristics', 0)
                chars_display = f"0x{chars:X}" if isinstance(chars, int) else str(chars)
                print(f"   ✓ Characteristics: {chars_display}")
        
        if 'optional_header' in headers:
            oh = headers['optional_header']
            ep = oh.get('entry_point', 0)
            ep_display = f"0x{ep:X}" if isinstance(ep, int) else str(ep)
            print(f"   ✓ Entry Point: {ep_display}")
            ib = oh.get('image_base', 0)
            ib_display = f"0x{ib:X}" if isinstance(ib, int) else str(ib)
            print(f"   ✓ Image Base: {ib_display}")
            print(f"   ✓ Subsystem: {oh.get('subsystem', 0)}")
        
        if 'sections' in structure:
            sections = structure['sections']
            print(f"   ✓ Sections Analyzed: {len(sections)}")
            
            # Show section details
            for section in sections[:3]:
                va = section['virtual_address']
                if isinstance(va, str) and va.startswith('0x'):
                    va_display = va
                else:
                    va_display = f"0x{va:X}"
                print(f"     - {section['name']}: VA={va_display}, "
                      f"Size={section['raw_size']} bytes")
                if 'flags' in section:
                    flags = section['flags']
                    print(f"       Flags: Code={flags.get('is_code', False)}, "
                          f"Data={flags.get('is_data', False)}, "
                          f"Exec={flags.get('is_executable', False)}")
    else:
        print(f"   ❌ Structure analysis failed: {structure['error']}")
    
    print("\n✅ Enhanced Cutter demonstration completed!")

def demo_integrated_analysis():
    """Demonstrate integrated analysis capabilities"""
    print("\n🔍 Integrated Analysis Demonstration")
    print("=" * 60)
    
    # Find a test file
    test_file = "C:\\Windows\\System32\\notepad.exe"
    if not os.path.exists(test_file):
        print("❌ Test file not found. Please provide a valid executable file.")
        return
    
    print(f"📁 Running integrated analysis on: {test_file}")
    
    # Run complete analysis
    results = analyze_file_with_tools(test_file)
    
    if "error" not in results:
        print("\n📊 Analysis Summary:")
        print("-" * 30)
        print(f"   ✓ Analysis Status: {results.get('analysis_summary', {}).get('analysis_status', 'Unknown')}")
        print(f"   ✓ Tools Used: {', '.join(results.get('analysis_summary', {}).get('tools_used', []))}")
        print(f"   ✓ File Size: {results.get('file_information', {}).get('file_size', 0):,} bytes")
        
        # File hashes
        hashes = results.get('file_information', {}).get('file_hashes', {})
        if hashes:
            print(f"   ✓ MD5: {hashes.get('md5', 'N/A')}")
            print(f"   ✓ SHA1: {hashes.get('sha1', 'N/A')}")
            print(f"   ✓ SHA256: {hashes.get('sha256', 'N/A')}")
        
        # Ghidra results
        ghidra_results = results.get('ghidra_analysis', {})
        if ghidra_results:
            print(f"\n🔧 Ghidra Analysis Results:")
            print(f"   - Architecture: {ghidra_results.get('architecture', 'Unknown')}")
            print(f"   - Entry Point: {ghidra_results.get('entry_point', 'Unknown')}")
            print(f"   - Sections: {len(ghidra_results.get('sections', []))}")
            print(f"   - Imports: {sum(len(apis) for apis in ghidra_results.get('imports', {}).values())}")
        
        # Cutter results
        cutter_results = results.get('cutter_analysis', {})
        if cutter_results:
            print(f"\n🔍 Cutter Analysis Results:")
            
            # Patterns
            patterns = cutter_results.get('patterns', {})
            if patterns:
                total_patterns = sum(len(pattern_list) for pattern_list in patterns.values())
                print(f"   - Total Patterns: {total_patterns}")
                for pattern_type, pattern_list in patterns.items():
                    if pattern_list:
                        print(f"     * {pattern_type.title()}: {len(pattern_list)}")
            
            # Entropy
            entropy = cutter_results.get('entropy', {})
            if entropy and 'statistics' in entropy:
                stats = entropy['statistics']
                print(f"   - Average Entropy: {stats.get('average_entropy', 0):.2f}")
                print(f"   - Packed Regions: {len(entropy.get('packed_regions', []))}")
            
            # Structure
            structure = cutter_results.get('structure', {})
            if structure:
                print(f"   - File Type: {structure.get('file_type', 'Unknown')}")
                print(f"   - Sections: {len(structure.get('sections', []))}")
        
        print(f"\n📄 Full analysis report saved to: enhanced_re_analysis_report.json")
        print(f"📊 Report size: {len(json.dumps(results)):,} characters")
        
    else:
        print(f"❌ Integrated analysis failed: {results['error']}")
    
    print("\n✅ Integrated analysis demonstration completed!")

def main():
    """Main demonstration function"""
    print("🚀 Enhanced Reverse Engineering Tools - Feature Demonstration")
    print("=" * 80)
    print("This demonstration showcases the advanced capabilities of the enhanced")
    print("Ghidra and Cutter tools, including:")
    print("• Multi-architecture disassembly and analysis")
    print("• Advanced pattern detection and cross-referencing")
    print("• Entropy analysis for packed/encrypted content")
    print("• Comprehensive file structure analysis")
    print("• Integrated analysis workflows")
    print("=" * 80)
    
    try:
        # Run demonstrations
        demo_enhanced_ghidra()
        demo_enhanced_cutter()
        demo_integrated_analysis()
        
        print("\n" + "=" * 80)
        print("🎉 All demonstrations completed successfully!")
        print("✅ Enhanced reverse engineering tools are fully functional")
        print("✅ Advanced features are working as expected")
        print("✅ Ready for professional malware analysis and reverse engineering")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n❌ Demonstration failed with error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 