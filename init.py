# Make it easier to import functions from different sets/challenges.

import sys, os

nsets = 2

for i in range(nsets):
    sys.path.append(os.getcwd() + '/set' + str(i+1))
