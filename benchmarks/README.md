# Cyber-Zero Benchmark Suite

To democratize the evaluation of cybersecurity agents, we provide three repaired benchmark suites adapted for EnIGMA+ in Cyber-Zero. The benchmarks are:

- [InterCode-CTF](https://github.com/princeton-nlp/intercode/tree/master/data/ctf)
- [NYU CTF Bench](https://nyu-llm-ctf.github.io/)
- [Cybench](https://Cybench.github.io/)

All benchmarks have been reformatted to follow the EnIGMA and EnIGMA+ specification. Each challenge includes:

- A `challenge.json` file
- A `docker-compose.yml` file (if an external server is required)

## ⚠️ Copyright Notice

All benchmark content remains the property of their original creators:

- **InterCode-CTF**: © [InterCode Benchmark team](https://intercode-benchmark.github.io/)
- **NYU CTF Bench**: © [NYU CTF Bench team](https://nyu-llm-ctf.github.io/)
- **Cybench**: © [Cybench team](https://cybench.github.io/)

This repository provides a patched version of the original benchmarks to resolved the identified issues in Cyber-Zero. We do **not** claim any ownership over the data or code from the original benchmarks.

## Identified Issues and Patches

### InterCode-CTF

We exclude 9 erroneous tasks from our experiments based on re-identified issues, which have been discussed in the [Dynamic Risk Assessments paper](https://arxiv.org/abs/2505.18384). As we use the InterCode-CTF data distributed by the EnIGMA team, Challenge 1's missing files are now provided.

#### Network Issues
Some challenges require connecting to PicoCTF servers that are no longer operational.  
**Affected challenges:** 28, 29, 87, 88, 89, 66, 95

#### Visual Flags
Some challenges contain multimodal input (images) that are incompatible with language-only agents.  
**Affected challenges:** 55, 56

### NYU CTF Bench

We exclude 8 erroneous challenges, and fix 1 challenge.

#### Repaired Challenges
- **`2018q-rev-a_walk_through_x86_part_1`**: Added missing Docker network server alias `rev.chal.csaw.io` and internal port `8000` to `challenge.json`
- **`2021q-rev-ransomware`**: Added missing `docker-compose.yml` file

#### Network Issues
Missing Docker configurations prevent proper server setup.  
**Affected challenges:** `2021q-web-scp_terminal`, `2023f-cry-nervcenter`, `2023f-cry-textbook_rsa`, `2023f-web-shreeramquest`, `2023q-web-philanthropy`, `2023q-web-rainbow_notes`, `2019f-web-biometric`

#### Missing Files
Challenge fails to start due to missing required files.  
**Affected challenges:** `2023f-for-forensings`

### Cybench

We fix 1 challenge.

#### Repaired Challenges
- **`cb-s22-crypto-ezmaze`**: Corrected Docker network server alias from `crypto.chal.csaw.io` to `crypt.chal.csaw.io`

## Citation

If you use this benchmark suite in your research, please cite:

```bibtex
@article{zhuo2025cyber,
  title={Training Cybersecurity Agents without Runtime},
  author={Zhuo, Terry Yue and Wang, Dingmin and Ding, Hantian and Kumar, Varun and Wang, Zijian},
  journal={arXiv preprint},
  year={2025},
}
```

## Acknowledgments

- [EnIGMA Project](https://enigma-agent.com)
- [Dynamic Risk Assessments](https://arxiv.org/abs/2505.18384)
