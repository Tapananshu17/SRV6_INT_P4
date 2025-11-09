cd p4src/
chmod +x compile.sh
./compile.sh 2>/dev/null
cd ..
sudo mn -c 1>/dev/null 2>/dev/null
sudo python3 mininet/topo.py --cli