"""koff — PS5 kernel offset cross-firming and verification engine.

The missing half of the scene's LLM-assisted offset workflow:
LLMs propose offsets; koff verifies them against captured/decrypted kernel
images and cross-firms them against the public offset tables.
"""

__version__ = "0.1.0"

KERNEL_VA_BASE = 0xFFFFFFFF80210000  # FreeBSD/Prospero kernel virtual base (kld-sdk)

from .model import Offset, OffsetTable, VerifyResult  # noqa: E402
from .kernel import KernelImage  # noqa: E402