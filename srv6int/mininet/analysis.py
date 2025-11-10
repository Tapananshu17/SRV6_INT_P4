import matplotlib.pyplot as plt
import numpy as np

with open('tmp/receiver_status.txt','r') as f:s = f.read()
stats = (x.strip().split() for x in s.split('\n') if x.strip())
stats = np.array([[float(t),int(n)] for t,n in stats])
t = stats[:,0]
n = stats[:,1]
with open('tmp/flood_start.txt','r') as f:t0 = float(f.read().strip())
with open('tmp/flood_end.txt','r') as f:s = f.read().split('\n')
t1 = float(s[0]) -t0
N = int(s[1].split(': ')[1])
t = t - t0
plt.plot(t,n,'-o')
plt.hlines(N,min(t),t1,'red')
plt.vlines(t1,0,N,'blue')
plt.xlabel("time (s)")
plt.ylabel("bytes")
plt.legend(["received","sent","done sending"])
plt.savefig("mininet/analysis.png",format="PNG")