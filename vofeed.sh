#!/bin/sh

# Raja Nandakumar. v0.1 23 April 2020.
#
# Script to run the vofeed.py file.
# Should work out of the box on the dunegpvm machines.

# The directory for the virtual environment
DIRDIR="voFeedVirtualEnv"

# Test if the directory. Otherwise create it and set up the environment
if [ -d "$DIRDIR" ]; then
    echo "Environment already created. Activating it."
    cd $DIRDIR
    . bin/activate
else
    mkdir $DIRDIR
    virtualenv --python=/usr/bin/python3 $DIRDIR
    cd $DIRDIR
    . bin/activate
    pip install --upgrade pip
    pip install htcondor
    pip install pyopenssl
fi
# Go to where the vofeed is actually there.
cd -

# At this point assume that the virtual environment is activated.
python vofeed.py
deactivate
