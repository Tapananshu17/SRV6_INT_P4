import json
import networkx as nx

# --- Input JSON ---
with open('mininet/flow.json') as f:data = json.load(f)

# --- Build network graph ---
G = nx.DiGraph()
for router, info in data.items():
    for neighbor, meta_L in info["out"].items():
        for meta in meta_L:
            G.add_edge(router, neighbor, ip=meta[0], mac=meta[1], port=meta[2])

# --- Infer OSPF next hops ---
for src in data.keys():
    paths = nx.single_source_dijkstra_path(G, src)
    out_infered = {}
    for dst, path in paths.items():
        if dst == src:continue
        # first hop after src in shortest path
        next_hop = path[1]
        ip, mac, port = data[src]["out"][next_hop][0]
        L = [[ip_in,mac,port] for ip_in,mac_in in data[dst]['in']]
        if L : out_infered[dst] = L
    data[src]["out_infered"] = out_infered

# --- Output the enriched JSON ---
with open('mininet/flow.json','w') as f:json.dump(data, f,indent=4)
