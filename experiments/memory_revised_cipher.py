import argparse, json, multiprocessing as mp, os, platform, statistics, sys
from pathlib import Path
import cryptography, psutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dcs_cipher import BLOCK_BYTES, decrypt_block, encrypt_block, encrypt_blocks, generate_round_keys

KEY=bytes.fromhex("0102040506AABBCC44DDEE8809040506")
SIZES=(1024*1024,10*1024*1024,50*1024*1024); OUTPUT=Path("revised_cipher_memory_v2.json")

def aes_transform(data,decrypt=False):
    cipher=Cipher(algorithms.AES(KEY),modes.ECB()); context=cipher.decryptor() if decrypt else cipher.encryptor()
    return context.update(data)+context.finalize()

def revised_transform_measured(data,round_keys,decrypt=False):
    """Retain bytearray and bytes result while RSS is read.

    This captures the short-lived overlap created by bytes(output), which a
    periodic external sampler can miss.
    """
    operation=decrypt_block if decrypt else encrypt_block; output=bytearray(len(data))
    for offset in range(0,len(data),BLOCK_BYTES):
        output[offset:offset+BLOCK_BYTES]=operation(data[offset:offset+BLOCK_BYTES],round_keys,True)
    result=bytes(output)
    checkpoint_rss=psutil.Process().memory_info().rss
    return result,checkpoint_rss

def worker(connection,algorithm,size,decrypt):
    process=psutil.Process(); round_keys=generate_round_keys(KEY); data=os.urandom(size)
    if decrypt: data=aes_transform(data) if algorithm.startswith("AES") else encrypt_blocks(data,round_keys,True)
    baseline=process.memory_info().rss
    if algorithm.startswith("AES"):
        result=aes_transform(data,decrypt); checkpoint=process.memory_info().rss
    else:
        result,checkpoint=revised_transform_measured(data,round_keys,decrypt)
    connection.send((max(0,checkpoint-baseline),baseline,checkpoint,len(result))); connection.close()

def measure(algorithm,size,decrypt):
    parent,child=mp.Pipe(); process=mp.Process(target=worker,args=(child,algorithm,size,decrypt)); process.start()
    increment,baseline,peak,_=parent.recv(); process.join()
    if process.exitcode!=0: raise RuntimeError(f"Memory worker failed: {process.exitcode}")
    return increment,baseline,peak

def summary(rows):
    values=[r[0] for r in rows]
    return {"runs":len(rows),"incremental_peak_values_bytes":values,"mean_incremental_peak_bytes":statistics.mean(values),"median_incremental_peak_bytes":statistics.median(values),"sd_incremental_peak_bytes":statistics.stdev(values),"mean_incremental_peak_MiB":statistics.mean(values)/(1024*1024),"baseline_rss_values_bytes":[r[1] for r in rows],"checkpoint_rss_values_bytes":[r[2] for r in rows]}

def save(records,runs):
    report={"environment":{"python":sys.version,"platform":platform.platform(),"cryptography":cryptography.__version__,"psutil":psutil.__version__},"method":{"metric":"incremental RSS at the operation's allocation checkpoint","tool":"psutil in a fresh worker process","repetitions":runs,"input_allocated_before_baseline":True,"revised_checkpoint":"RSS read while output bytearray and converted bytes result are both retained","aes_checkpoint":"RSS read while returned bytes result is retained","raw_block_mode":"ECB-style independent blocks for laboratory measurement only","comparison_scope":"implementation-level memory measurement"},"records":records}
    OUTPUT.write_text(json.dumps(report,indent=2),encoding="utf-8")

def main():
    mp.freeze_support(); parser=argparse.ArgumentParser(description="Corrected peak-memory benchmark")
    parser.add_argument("--max-size-mib",type=int,default=50); parser.add_argument("--runs",type=int,default=3); args=parser.parse_args()
    if args.runs<3: raise ValueError("Use at least three repetitions.")
    records=[]
    for size in [s for s in SIZES if s<=args.max_size_mib*1024*1024]:
        for algorithm in ("Revised-with-DCS","AES-128-OpenSSL-backend"):
            enc=[measure(algorithm,size,False) for _ in range(args.runs)]; print(f"Measured encryption memory: {algorithm}, {size} bytes",flush=True)
            dec=[measure(algorithm,size,True) for _ in range(args.runs)]; print(f"Measured decryption memory: {algorithm}, {size} bytes",flush=True)
            records.append({"algorithm":algorithm,"size_bytes":size,"encryption":summary(enc),"decryption":summary(dec)}); save(records,args.runs)
    print(f"Created {OUTPUT}")

if __name__=="__main__": main()
