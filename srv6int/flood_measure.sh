sudo mn -c 1>/dev/null 2>/dev/null
sudo python3 mininet/topo.py mininet/mininet_script_flood.txt 
sudo python3 mininet/analysis.py