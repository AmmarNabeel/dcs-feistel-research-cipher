# Reproducibility checklist

- [ ] Record the Git commit hash used for the manuscript revision.
- [ ] Create a versioned GitHub release and archive it with a DOI service if available.
- [ ] Record Python, package, operating-system, CPU, and RAM versions.
- [ ] Run `pytest` and retain the terminal output.
- [ ] Run experiments in a clean output directory.
- [ ] Do not overwrite the archived `results/` files with reduced smoke-test runs.
- [ ] Report any deviation from the seeds, sample sizes, or package versions.
- [ ] Treat timing and memory values as platform-dependent.
- [ ] Keep the research-prototype and non-deployment warning in the README.
