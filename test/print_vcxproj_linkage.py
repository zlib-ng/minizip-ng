import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# ---------------------------------------------------------
# Generic Search Function
# ---------------------------------------------------------
def find_element_by_predicate(root, xpath, ns, predicate):
    for element in root.findall(xpath, ns):
        if predicate(element):
            return element
    return None

# ---------------------------------------------------------
# Matcher Factories (Closures)
# ---------------------------------------------------------
def make_label_matcher(label_val):
    def matcher(element):
        return (element.get('Label') == label_val)
    return matcher

def make_condition_matcher(label_val, condition_val):
    def matcher(element):
        return (element.get('Label') == label_val and 
                element.get('Condition') == condition_val)
    return matcher

def make_include_matcher(include_val):
    def matcher(element):
        return include_val in element.get('Include')
    return matcher

def print_globals(root, ns):
    found_globals = find_element_by_predicate(root,
                                              'm:PropertyGroup',
                                              ns,
                                              make_label_matcher('Globals'))

    print(f"\tProject GUID: {found_globals.find('m:ProjectGuid', ns).text}")

    found_conf = find_element_by_predicate(root,
                                           'm:PropertyGroup',
                                           ns,
                                           make_condition_matcher("Configuration", "'$(Configuration)|$(Platform)'=='Release|x64'"))

    print(f"\tConfigurationType: {found_conf.find('m:ConfigurationType', ns).text}")

def print_reference(root, ns):
    found_ref = find_element_by_predicate(root,
                                          'm:ItemGroup/m:ProjectReference',
                                           ns,
                                           make_include_matcher(r"build\_deps\zlib-build\zlib"))

    print(f"\tReference Name: {found_ref.find('m:Name', ns).text}")
    print(f"\tReference Project: {found_ref.find('m:Project', ns).text}")

def print_parent(file, ns):
    try:
        print(f"{file}:")
        if not Path(file).exists():
            print("\t(file not found)")
        else:
            tree = ET.parse(file)
            root = tree.getroot()
            print_globals(root, ns)
            print_reference(root, ns)
        print()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")

def print_child(file, ns):
    try:
        print(f"{file}:")
        if not Path(file).exists():
            print("\t(file not found)")
        else:
            tree = ET.parse(file)
            root = tree.getroot()
            print_globals(root, ns)
        print()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")

# ---------------------------------------------------------
# Main Execution
# ---------------------------------------------------------
def main():
    ns = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}

    print_parent('../build/minizip.vcxproj', ns)
    print_child('../build/_deps/zlib-build/zlib.vcxproj', ns)
    print_child('../build/_deps/zlib-build/zlibstatic.vcxproj', ns)

if __name__ == "__main__":
    main()
