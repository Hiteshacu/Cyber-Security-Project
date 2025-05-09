#!C:\Users\HITESH A\Desktop\College\Hackathon3\venv\Scripts\python.exe

# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function
from builtins import object
import sys

from optparse import OptionParser
from androguard.core.analysis import auto

option_0 = {
    'name': ('-d', '--directory'),
    'help': 'directory input',
    'nargs': 1
}
option_1 = {'name': ('-v', '--verbose'), 'help': 'add debug', 'action': 'count'}
options = [option_0, option_1]


class AndroLog(object):
    def __init__(self, id_file, filename):
        self.id_file = id_file
        self.filename = filename


class AndroTest(auto.DirectoryAndroAnalysis):
    def analysis_app(self, log, apkobj, dexobj, adexobj):
        print(log.id_file, log.filename, apkobj, dexobj, adexobj)


def main(options, arguments):
    if options.directory:
        settings = {
            "my": AndroTest(options.directory),
            "log": AndroLog,
            "max_fetcher": 3,
        }

        aa = auto.AndroAuto(settings)
        aa.go()


if __name__ == "__main__":
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
