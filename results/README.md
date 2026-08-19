# Archived manuscript results

These JSON and CSV files are the machine-readable outputs used in the revised
manuscript. They should be treated as immutable release artifacts. New runs
should be written to a separate directory.

The processing-time and memory outputs are specific to the Windows computer
recorded in those JSON files. Seeded statistical outputs retain the platform
and package metadata of the run that produced each file when applicable. They
are reproducible from the fixed seeds and stated sample sizes, subject to
numerical-library differences.

Use `sha256sum -c RESULTS_MANIFEST.sha256` from this directory to verify file
integrity on systems that provide `sha256sum`.
