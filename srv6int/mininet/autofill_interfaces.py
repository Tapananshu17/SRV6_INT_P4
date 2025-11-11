import sys
filename = sys.argv[1]
with open(filename,'r') as f: s= f.read()
if not s.strip():
    print("Empty file")
    sys.exit(1)
s = [[y.strip() for y in x.strip().split(',')] for x in s.split('\n')]

def parse_name(A:str) -> tuple[bool,str]:
    if A.startswith('s'):A_is_switch = True
    elif A.startswith('h'):A_is_switch = False
    else:
        print("incorrect name :",A,"\nNames can only start with 's' or 'h'")
        sys.exit(1)
    A_num = A[1:].strip()
    if not A_num:
        print("incorrect name :",A,"\nNames must have a number after first character.")
        sys.exit(1)
    try: A_num = int(A_num)
    except:
        print("incorrect name :",A)
        sys.exit(1)
    if A_is_switch and (A_num <= 0 or A_num > 6):
        print("incorrect name :",A,"\nSwitch number should be between 1 and 6 (inclusive)")
        sys.exit(1) 
    if (not A_is_switch) and (A_num <= 0 or A_num > 9):
        print("incorrect name :",A,"\nSwitch number should be between 1 and 9 (inclusive)")
        sys.exit(1) 
    return A_is_switch,A_num

def suggest_ads(A:str,B:str) -> list[str]:
    s_A,n_A = parse_name(A)
    s_B,n_B = parse_name(B)
    flipped = False
    if s_A and s_B: 
        n_A = "abcdef"[n_A-1]
        n_B = "abcdef"[n_B-1]
        IP_A = f"2001:1:{n_B}::f{n_A}/128"
        MAC_A = f"00:00:00:00:00:{n_B}{n_A}"
        IP_B = f"2001:1:{n_A}::f{n_B}/128"
        MAC_B = f"00:00:00:00:00:{n_A}{n_B}"
        return IP_A,MAC_A,IP_B,MAC_B
    elif not (s_A or s_B):
        print("incorrect edge",(A,B),"\nOne of the ends must be a switch.")
    elif s_B: # flip
        flipped = True
        s_A,s_B = s_B,s_A
        n_A,n_B = n_B,n_A
    MAC_B = f"00:00:00:00:00:{n_B}{n_A-1}"
    IP_B = f"2001:1:{n_B}::{n_A}/128"
    n_A = "abcdef"[n_A-1]
    IP_A = f"2001:1:{n_B}::f{n_A}/128"
    MAC_A = f"00:00:00:00:00:{n_B}{n_A}"
    if flipped:return IP_B,MAC_B,IP_A,MAC_A
    else: return IP_A,MAC_A,IP_B,MAC_B

for line in s[1:]:
    if len(line) <=1: continue
    A,B = line[0].strip(),line[1].strip()
    if not B : continue
    ads = suggest_ads(A,B)
    for i in range(4):
        if not line[2+i]: line[2+i] = ads[i]
    
s = "\n".join([",".join(x) for x in s])
with open(filename,'w') as f: f.write(s)