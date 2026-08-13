# Third-party dependency notices

No third-party source code is vendored. The frozen runtime resolves the packages
below from PyPI; each remains governed by its own upstream licence. Versions are
recorded by `uv.lock` and `artifacts/requirements-runtime.txt`.

| Package | Version | Upstream | Licence expression |
|---|---:|---|---|
| annotated-types | 0.8.0 | https://github.com/annotated-types/annotated-types | MIT |
| cffi | 2.1.1 | https://github.com/python-cffi/cffi | MIT |
| cryptography | 50.0.0 | https://github.com/pyca/cryptography | Apache-2.0 OR BSD-3-Clause |
| pycparser | 3.0 | https://github.com/eliben/pycparser | BSD-3-Clause |
| pydantic | 2.13.4 | https://github.com/pydantic/pydantic | MIT |
| pydantic-core | 2.46.4 | https://github.com/pydantic/pydantic-core | MIT |
| rfc8785 | 0.1.4 | https://github.com/trailofbits/rfc8785.py | Apache-2.0 |
| securesystemslib | 1.4.0 | https://github.com/secure-systems-lab/securesystemslib | MIT |
| typing-extensions | 4.16.0 | https://github.com/python/typing_extensions | PSF-2.0 |
| typing-inspection | 0.4.4 | https://github.com/pydantic/typing-inspection | MIT |

This inventory records the installed metadata and upstream licence files used
for the Stage-1 environment; it is not legal advice. Re-resolve and re-audit
licences before any production distribution.
