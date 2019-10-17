from os.path import abspath, dirname
import ycm_core

flags = [
    '-std=gnu11',
    '-Wall',
    '-Wextra',
    '-pedantic',
    '-D_GNU_SOURCE',
    '-x', 'c',
    '-I', '.',
]

def DirectoryOfThisScript():
    return dirname(abspath(__file__))

def Settings(filename, language, **kwargs):
    if language == 'cfamily':
        return {
            'flags': flags,
            'include_paths_relative_to_dir': DirectoryOfThisScript()
        }

    return {}

