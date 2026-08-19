import argparse, csv, json, math, random, statistics
from pathlib import Path
from dcs_cipher import SBOX, encrypt_block, generate_round_keys

SEED = 20260814

def popcount(value): return bin(value).count("1")
def hamming(a, b): return popcount(int.from_bytes(a,"big") ^ int.from_bytes(b,"big"))

def ci95_independent(values):
    mean, sd = statistics.mean(values), statistics.stdev(values)
    half = 1.96 * sd / math.sqrt(len(values))
    return sd, mean-half, mean+half

def plaintext_avalanche(plaintexts, key, rounds, use_dcs):
    all_values, sample_means = [], []
    round_keys = generate_round_keys(key, rounds)
    for plaintext in plaintexts:
        baseline, original = encrypt_block(plaintext, round_keys, use_dcs), int.from_bytes(plaintext,"big")
        values = [hamming(baseline, encrypt_block((original^(1<<bit)).to_bytes(16,"big"), round_keys, use_dcs)) for bit in range(128)]
        all_values.extend(values); sample_means.append(statistics.mean(values))
    return all_values, sample_means

def key_avalanche(keys, plaintext, rounds, use_dcs):
    all_values, sample_means = [], []
    for key in keys:
        baseline, original = encrypt_block(plaintext,generate_round_keys(key,rounds),use_dcs), int.from_bytes(key,"big")
        values=[]
        for bit in range(128):
            modified=(original^(1<<bit)).to_bytes(16,"big")
            values.append(hamming(baseline,encrypt_block(plaintext,generate_round_keys(modified,rounds),use_dcs)))
        all_values.extend(values); sample_means.append(statistics.mean(values))
    return all_values, sample_means

def sac_matrix(plaintexts, key, rounds, use_dcs):
    counts=[[0]*128 for _ in range(128)]; round_keys=generate_round_keys(key,rounds)
    for plaintext in plaintexts:
        baseline=int.from_bytes(encrypt_block(plaintext,round_keys,use_dcs),"big"); original=int.from_bytes(plaintext,"big")
        for input_bit in range(128):
            changed=(original^(1<<input_bit)).to_bytes(16,"big")
            difference=baseline^int.from_bytes(encrypt_block(changed,round_keys,use_dcs),"big")
            for output_bit in range(128): counts[input_bit][output_bit]+=(difference>>output_bit)&1
    probabilities=[c/len(plaintexts) for row in counts for c in row]
    return {"samples_per_input_bit":len(plaintexts),"matrix_cells":len(probabilities),"mean_probability":statistics.mean(probabilities),"mean_absolute_deviation_from_0.5":statistics.mean(abs(p-.5) for p in probabilities),"min_probability":min(probabilities),"max_probability":max(probabilities)}

def sbox_metrics():
    ddt=[[0]*16 for _ in range(16)]
    for dx in range(16):
        for x in range(16): ddt[dx][SBOX[x]^SBOX[x^dx]]+=1
    max_ddt=max(max(row) for row in ddt[1:]); lat=[[0]*16 for _ in range(16)]
    for a in range(16):
        for b in range(16):
            lat[a][b]=sum(1 if ((popcount(a&x)^popcount(b&SBOX[x]))&1)==0 else -1 for x in range(16))
    max_lat=max(abs(lat[a][b]) for a in range(1,16) for b in range(1,16))
    nonlinearities=[8-max(abs(lat[a][b]) for a in range(16))//2 for b in range(1,16)]
    return {"bijective":len(set(SBOX))==16,"differential_uniformity":max_ddt,"maximum_differential_probability":max_ddt/16,"maximum_absolute_LAT_entry":max_lat,"component_nonlinearity_min":min(nonlinearities),"component_nonlinearity_values":nonlinearities}

def summarize(label, values, sample_means, rounds, use_dcs, analysis):
    independent_sd, low, high=ci95_independent(sample_means)
    return {"analysis":analysis,"label":label,"rounds":rounds,"use_dcs":use_dcs,"bit_flip_observations":len(values),"independent_samples_for_ci":len(sample_means),"mean_hamming_bits":statistics.mean(values),"mean_percentage":statistics.mean(values)/128*100,"sd_hamming_bits_across_bit_flips":statistics.stdev(values),"sd_of_independent_sample_means":independent_sd,"min_hamming_bits":min(values),"max_hamming_bits":max(values),"ci95_mean_hamming_bits_clustered":[low,high]}

def main():
    parser=argparse.ArgumentParser(description="Reproducible avalanche, SAC, and S-box analysis")
    parser.add_argument("--samples",type=int,default=100); parser.add_argument("--sac-samples",type=int,default=100); args=parser.parse_args()
    if min(args.samples,args.sac_samples)<30: raise ValueError("Use at least 30 independent samples.")
    rng=random.Random(SEED); fixed_key=rng.randbytes(16); plaintexts=[rng.randbytes(16) for _ in range(args.samples)]
    fixed_plaintext=rng.randbytes(16); keys=[rng.randbytes(16) for _ in range(args.samples)]
    sac_key=rng.randbytes(16); sac_plaintexts=[rng.randbytes(16) for _ in range(args.sac_samples)]; records=[]
    for rounds in (3,5,7,9):
        for use_dcs in (False,True):
            values,means=plaintext_avalanche(plaintexts,fixed_key,rounds,use_dcs)
            records.append(summarize("with DCS" if use_dcs else "without DCS",values,means,rounds,use_dcs,"plaintext_bit_flip")); print(f"Completed plaintext avalanche: rounds={rounds}, DCS={use_dcs}",flush=True)
    for use_dcs in (False,True):
        values,means=key_avalanche(keys,fixed_plaintext,7,use_dcs)
        records.append(summarize("with DCS" if use_dcs else "without DCS",values,means,7,use_dcs,"key_bit_flip")); print(f"Completed key avalanche: DCS={use_dcs}",flush=True)
    report={"method":{"seed":SEED,"paired_ablation_inputs":True,"ci_unit":"independent plaintext or key sample; 128 bit flips are clustered within it","plaintext_samples_per_configuration":args.samples,"key_samples_per_configuration":args.samples},"records":records,"sac_7_rounds":{"without_dcs":sac_matrix(sac_plaintexts,sac_key,7,False),"with_dcs":sac_matrix(sac_plaintexts,sac_key,7,True)},"sbox":sbox_metrics()}
    Path("revised_cipher_analysis_v2.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    with Path("revised_cipher_analysis_v2.csv").open("w",newline="",encoding="utf-8") as stream:
        writer=csv.DictWriter(stream,fieldnames=list(records[0])); writer.writeheader(); writer.writerows(records)
    print("Created revised_cipher_analysis_v2.json and revised_cipher_analysis_v2.csv")

if __name__=="__main__": main()
