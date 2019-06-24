# Make it easier to import functions from different sets/challenges.

import sys, os

nsets = 8

for i in range(nsets):
    if os.path.isdir(os.getcwd() + '/set' + str(i+1)):
        sys.path.append(os.getcwd() + '/set' + str(i+1))
