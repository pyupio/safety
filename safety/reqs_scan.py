# Python code to search for requirements files
import os
import random

def scan_file(root, filename):
    if filename.endswith('requirements.txt'):
        file_name_randomizer = round(random.random()*100000000)
        filepath = f"{root}/{str(filename)}"
        print(f"    Scanning {filepath} using safety check")
        os.system(f"safety check -r {filepath} --cache 100 --output json >> {save_results_path}/{file_name_randomizer}-scan.json")

def check_file_name(root, filename):
    if filename.endswith('requirements.txt') or filename.endswith('pyproject.toml') or filename.endswith('poetry.lock') or filename.endswith('Pipfile') or filename.endswith('Pipfile.lock'):
        print (f"found requirements file: {root}/{str(filename)}")
        scan_file(root, filename)

# From https://gist.github.com/TheMatt2/faf5ca760c61a267412c46bb977718fa
def walklevel(path, depth = 1, deny_list = []):
    """It works just like os.walk, but you can pass it a level parameter
       that indicates how deep the recursion will go.
       If depth is 1, the current directory is listed.
       If depth is 0, nothing is returned.
       If depth is -1 (or less than 0), the full depth is walked.
    """

    # If depth is negative, just walk
    # Not using yield from for python2 compat
    # and copy dirs to keep consistant behavior for depth = -1 and depth = inf
    if depth < 0:
        for root, dirs, files in os.walk(path):
            yield root, dirs[:], files
        return
    elif depth == 0:
        return

    # path.count(os.path.sep) is safe because
    # - On Windows "\\" is never allowed in the name of a file or directory
    # - On UNIX "/" is never allowed in the name of a file or directory
    # - On MacOS a literal "/" is quitely translated to a ":" so it is still
    #   safe to count "/".
    base_depth = path.rstrip(os.path.sep).count(os.path.sep)
    for root, dirs, files in os.walk(path):
        for idx, directory in enumerate(dirs):
            if f"{root}{directory}" in deny_list:
                print(f"Not scanning {root}{directory}")
                del dirs[idx]
        yield root, dirs[:], files
        cur_depth = root.count(os.path.sep)
        if base_depth + depth <= cur_depth:
            del dirs[:]



# This is to get the directory that the program
# is currently running in.
current_path = os.path.dirname(os.path.realpath(__file__))
save_results_path = f"{current_path}/.demo_safety_scan_results"
starting_path = "/"
print(f"Scanning from {starting_path}")
     
folder_depth_limit = 8
paths_excluded_list = ["/System"]

# Create folder for scan results
os.system(f"mkdir {save_results_path}")

for root, dirs, files in walklevel(starting_path, folder_depth_limit, paths_excluded_list):
    for file in files:
        check_file_name(root, file)
