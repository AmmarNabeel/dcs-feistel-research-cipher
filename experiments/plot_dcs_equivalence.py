import matplotlib.pyplot as plt

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 12,
    "font.weight": "bold",
    "axes.labelsize": 12,
    "axes.labelweight": "bold",
    "xtick.labelsize": 12,
    "ytick.labelsize": 12,
    "legend.fontsize": 12,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})


POINT = 0.00525
CI90 = (-0.0461708, 0.0566708)
CI95 = (-0.0560566, 0.0665566)
MARGIN = 1.0


fig, ax = plt.subplots(figsize=(8.2, 3.8))

# Equivalence region and reference lines.
ax.axvspan(-MARGIN, MARGIN, color="#d9ead3", alpha=0.75,
           label="Equivalence region")
ax.axvline(-MARGIN, color="#38761d", linestyle="--", linewidth=1.4)
ax.axvline(MARGIN, color="#38761d", linestyle="--", linewidth=1.4)
ax.axvline(0, color="black", linestyle=":", linewidth=1.3)

# Nested confidence intervals around the paired estimate.
ax.errorbar(
    POINT, 1.0,
    xerr=[[POINT - CI95[0]], [CI95[1] - POINT]],
    fmt="none", ecolor="#6c757d", elinewidth=7, capsize=0,
    label="95% CI",
)
ax.errorbar(
    POINT, 1.0,
    xerr=[[POINT - CI90[0]], [CI90[1] - POINT]],
    fmt="o", color="#b22222", ecolor="#b22222",
    markersize=7, elinewidth=3, capsize=6,
    label="90% TOST CI",
)

ax.set_xlim(-1.18, 1.18)
ax.set_ylim(0.55, 1.45)
ax.set_yticks([1.0])
ax.set_yticklabels(["With DCS minus without DCS"])
for label in ax.get_xticklabels() + ax.get_yticklabels():
    label.set_fontweight("bold")
ax.set_xlabel("Paired difference in mean ciphertext Hamming distance (bits)")
ax.grid(axis="x", alpha=0.25)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=3,
          frameon=False, prop={"family": "serif", "size": 12, "weight": "bold"})

ax.annotate(
    "Estimate = 0.00525 bit",
    xy=(POINT, 1.0), xytext=(0.20, 1.25),
    arrowprops={"arrowstyle": "->", "color": "#444444"},
    fontsize=12, fontweight="bold",
)
ax.text(-MARGIN, 0.66, "-1-bit margin", ha="center", va="center",
        fontsize=12, fontweight="bold")
ax.text(MARGIN, 0.66, "+1-bit margin", ha="center", va="center",
        fontsize=12, fontweight="bold")

fig.tight_layout()
fig.subplots_adjust(bottom=0.30)
fig.savefig("dcs_avalanche_equivalence.pdf", bbox_inches="tight")
fig.savefig("dcs_avalanche_equivalence.png", dpi=300, bbox_inches="tight")
