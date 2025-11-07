with open('mininet/interfaces.csv','r') as f:edges = f.read()
edges = edges.split('\n')[1:]
edges = [edge.split(',') for edge in edges if edge.strip()]
edges = {(edge[0],edge[1]):[x.split('/')[0] for x in edge[2:]] for edge in edges}
nodes = []
for x,y in edges:nodes.extend([x,y])
nodes = list(set(nodes))
rev_lookup = {}
for x,y in edges.items():
    A,B = x
    IP_A,MAC_A,IP_B,MAC_B = y
    rev_lookup[(B,IP_A)] = A
    rev_lookup[(A,IP_B)] = B

def lookup(current_node,next_node):
    global edges,nodes
    A = current_node
    if not A in nodes: return None
    B = next_node
    if (A,B) in edges:
        IP_A,MAC_A,IP_B,MAC_B = edges[(A,B)]
    elif (B,A) in edges:
        IP_B,MAC_B,IP_A,MAC_A = edges[(B,A)]
    else: return None
    return IP_B,MAC_B

def path_lookup(current_node,path,f=None):
    SIDs = []
    if isinstance(path,str):path = [x.strip() for x in path.split(',')]
    for node in path:
        if ":" in node or '.' in node:
            if (current_node,node) not in rev_lookup: 
                print(f"path {path} doesn't exist",file=f)
                return None
            next_node = rev_lookup[(current_node,node)]
            next_SID = node
        else:
            next_node = node
            next_SID = lookup(current_node,next_node)
            if next_SID is None:
                print("path doesn't exist")
                return None
            else:next_SID = next_SID[0]
        SIDs.append(next_SID)
        current_node = next_node
    return SIDs
        
if __name__=="__main__":
    import sys
    if any(sys.argv[0].startswith(x+str(y)) 
        for x in 'chsr' for y in range(10)):
        args = sys.argv[1:]
    else:args= sys.argv
    current_node = args[1]
    path = args[2]   
    if "--node" in sys.argv:print(lookup(current_node,path)) 
    else:print(path_lookup(current_node,path))