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


# # --- Combined summary figure ---
# fig, axs = plt.subplots(3,1, figsize=(9,10), sharex=True)

# # throughput panel
# if len(t) >= 2:
#     dt = np.diff(t)
#     dbytes = np.diff(n)
#     mask = dt>0
#     t_mid = t[:-1][mask] + dt[mask]/2.0
#     rate = np.zeros_like(dbytes); rate[mask] = dbytes[mask] / dt[mask]
#     axs[0].plot(t_mid, rate, alpha=0.5)
#     axs[0].plot(t_mid, moving_avg(rate, w=5), '-r', linewidth=1.5)
#     axs[0].set_ylabel('bytes/sec')
#     axs[0].grid(True, alpha=0.25)
# else:
#     axs[0].text(0.5, 0.5, 'insufficient samples for throughput', ha='center', va='center')

# # cumulative percent panel
# if N > 0:
#     pct = 100.0 * n / float(N)
#     axs[1].plot(t, pct, '-o', markersize=3)
#     axs[1].set_ylabel('received (%)')
#     axs[1].grid(True, alpha=0.25)
# else:
#     axs[1].text(0.5, 0.5, 'N not provided', ha='center', va='center')

# # inter-arrival panel
# if len(t) >= 2:
#     inter = np.diff(t)
#     axs[2].hist(inter, bins=50, color='C2', alpha=0.8)
#     axs[2].set_xlabel('time (s)')
#     axs[2].set_ylabel('inter-arrival count')
#     axs[2].grid(True, alpha=0.25)
# else:
#     axs[2].text(0.5, 0.5, 'insufficient samples for inter-arrival', ha='center', va='center')

# plt.tight_layout()
# plt.savefig('mininet/analysis_summary.png', dpi=200, format='PNG')
# plt.close()