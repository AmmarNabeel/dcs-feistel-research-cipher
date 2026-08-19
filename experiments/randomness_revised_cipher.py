import argparse, json, math, platform, random, statistics, sys
from pathlib import Path
import numpy as np
import scipy
from scipy.special import gammaincc
from dcs_cipher import encrypt_blocks, generate_round_keys

SEED=20260815; ALPHA=0.01; OUTPUT=Path("revised_cipher_randomness.json")

def structured_plaintext(stream_index,size):
    prefix=stream_index.to_bytes(8,"big")
    return b"".join(prefix+counter.to_bytes(8,"big") for counter in range(size//16))

def pattern_counts(bits,m):
    n=len(bits); extended=np.concatenate((bits,bits[:m-1])); codes=np.zeros(n,dtype=np.uint16)
    for shift in range(m): codes=(codes<<1)|extended[shift:shift+n]
    return np.bincount(codes,minlength=1<<m)

def frequency(bits):
    n=len(bits); statistic=abs(2*int(bits.sum())-n)/math.sqrt(n)
    return math.erfc(statistic/math.sqrt(2))

def block_frequency(bits,block_size=128):
    blocks=bits[:len(bits)//block_size*block_size].reshape(-1,block_size)
    chi=4*block_size*float(np.square(blocks.mean(axis=1)-.5).sum())
    return float(gammaincc(len(blocks)/2,chi/2))

def runs(bits):
    n=len(bits); pi=float(bits.mean())
    if abs(pi-.5)>=2/math.sqrt(n): return 0.0
    transitions=int(np.count_nonzero(bits[1:]!=bits[:-1])); v=transitions+1
    return math.erfc(abs(v-2*n*pi*(1-pi))/(2*math.sqrt(2*n)*pi*(1-pi)))

def longest_run(bits):
    block_size=10000; blocks=bits[:len(bits)//block_size*block_size].reshape(-1,block_size)
    observed=[0]*7
    for block in blocks:
        padded=np.concatenate(([0],block,[0])); changes=np.flatnonzero(padded[1:]!=padded[:-1]); lengths=changes[1::2]-changes[::2]
        longest=int(lengths.max()) if len(lengths) else 0
        category=0 if longest<=10 else 6 if longest>=16 else longest-10
        observed[category]+=1
    probabilities=(0.0882,0.2092,0.2483,0.1933,0.1208,0.0675,0.0727); number=len(blocks)
    chi=sum((o-number*p)**2/(number*p) for o,p in zip(observed,probabilities))
    return float(gammaincc(3,chi/2))

def psi2(counts,n,m): return float(np.square(counts,dtype=np.float64).sum())*(1<<m)/n-n

def entropy_and_serial(bits,m=10):
    n=len(bits); counts={k:pattern_counts(bits,k) for k in (m+1,m,m-1,m-2)}
    def phi(k):
        nonzero=counts[k][counts[k]>0]; probabilities=nonzero/n
        return float(np.sum(probabilities*np.log(probabilities)))
    apen=phi(m)-phi(m+1); chi=2*n*(math.log(2)-apen)
    approximate_entropy=float(gammaincc(1<<(m-1),chi/2))
    psim=psi2(counts[m],n,m); psim1=psi2(counts[m-1],n,m-1); psim2=psi2(counts[m-2],n,m-2)
    delta1=psim-psim1; delta2=psim-2*psim1+psim2
    return approximate_entropy,float(gammaincc(1<<(m-2),delta1/2)),float(gammaincc(1<<(m-3),delta2/2))

def uniformity_p_value(pvalues):
    bins=np.histogram(pvalues,bins=np.linspace(0,1,11))[0]; expected=len(pvalues)/10
    chi=float(np.square(bins-expected).sum()/expected)
    return float(gammaincc(9/2,chi/2)),bins.tolist()

def evaluate(ciphertext):
    bits=np.unpackbits(np.frombuffer(ciphertext,dtype=np.uint8)); apen,serial1,serial2=entropy_and_serial(bits)
    return {"frequency":frequency(bits),"block_frequency":block_frequency(bits),"runs":runs(bits),"longest_run":longest_run(bits),"approximate_entropy":apen,"serial_1":serial1,"serial_2":serial2}

def aggregate(records,use_dcs,streams):
    subset=[r for r in records if r["use_dcs"]==use_dcs]; names=list(subset[0]["p_values"]); tests={}
    lower=(1-ALPHA)-3*math.sqrt(ALPHA*(1-ALPHA)/streams); upper=(1-ALPHA)+3*math.sqrt(ALPHA*(1-ALPHA)/streams)
    for name in names:
        values=[r["p_values"][name] for r in subset]; passed=sum(p>=ALPHA for p in values); uniform,bins=uniformity_p_value(values)
        tests[name]={"passed_streams":passed,"total_streams":streams,"pass_proportion":passed/streams,"expected_proportion_interval_3sigma":[max(0,lower),min(1,upper)],"proportion_acceptable":passed/streams>=lower,"p_value_uniformity":uniform,"uniformity_acceptable":uniform>=0.0001,"p_value_bins":bins,"min_p_value":min(values),"median_p_value":statistics.median(values)}
    return tests

def main():
    parser=argparse.ArgumentParser(description="NIST-style randomness assessment of structured counter plaintexts")
    parser.add_argument("--streams",type=int,default=100); parser.add_argument("--size-kib",type=int,default=128); parser.add_argument("--only-dcs",action="store_true"); args=parser.parse_args()
    if args.streams<55: raise ValueError("Use at least 55 streams for p-value uniformity; 100 is recommended.")
    size=args.size_kib*1024
    if size%16 or size<128*1024: raise ValueError("Use a multiple of 16 bytes and at least 128 KiB.")
    rng=random.Random(SEED); records=[]; configurations=(True,) if args.only_dcs else (False,True)
    for stream_index in range(args.streams):
        key=rng.randbytes(16); plaintext=structured_plaintext(stream_index,size); round_keys=generate_round_keys(key)
        for use_dcs in configurations:
            from dcs_cipher import encrypt_blocks
            ciphertext=encrypt_blocks(plaintext,round_keys,use_dcs); pvalues=evaluate(ciphertext)
            records.append({"stream":stream_index,"use_dcs":use_dcs,"size_bytes":size,"p_values":pvalues})
        if (stream_index+1)%10==0: print(f"Completed {stream_index+1}/{args.streams} streams",flush=True)
    report={"environment":{"python":sys.version,"platform":platform.platform(),"numpy":np.__version__,"scipy":scipy.__version__},"method":{"seed":SEED,"alpha":ALPHA,"streams_per_configuration":args.streams,"bytes_per_stream":size,"plaintext":"unique 64-bit stream identifier concatenated with sequential 64-bit counters","independent_key_per_stream":True,"interpretation":"NIST-style subset; this is empirical evidence, not a proof of cryptographic security"},"summary":{"without_dcs":aggregate(records,False,args.streams) if False in configurations else None,"with_dcs":aggregate(records,True,args.streams)},"records":records}
    OUTPUT.write_text(json.dumps(report,indent=2),encoding="utf-8"); print(f"Created {OUTPUT}")

if __name__=="__main__": main()
