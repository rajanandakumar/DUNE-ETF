# DUNE-ETF

vofeed.sh : Steering programme (does virtualenv and the other stuff) to run vofeed.py
vofeed.py : Creates the vofeed.xml from the glide-in configuration

checkStatus.py : Checks the ETF tests, removes the CEs which are "down" in the gocDB and other CEs with ignorable issues and gives a list of the remaining "good" CEs which are failing the DUNE ETF tests.
