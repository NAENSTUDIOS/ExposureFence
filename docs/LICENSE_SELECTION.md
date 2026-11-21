# ExposureFence — Software License Selection & Attribution Analysis

**Document Purpose:** In accordance with open-source release protocols, this document presents the legal and architectural implications of software licenses for ExposureFence.  
**Decision Authority:** Repository Owner (NAENSTUDIOS).  
**Status:** **PENDING REPOSITORY OWNER DECISION.**  

---

## 1. Third-Party Dependency License & Attribution Audit

ExposureFence relies on standard open-source Python libraries. An audit of their respective licenses confirms compatibility with standard permissive open-source distribution:

| Dependency | Version | Upstream License | Distribution Compatibility |
| :--- | :--- | :--- | :--- |
| **`boto3`** | `1.36.0` | Apache License 2.0 | Compatible with Apache 2.0, MIT, BSD |
| **`botocore`** | `1.36.0` | Apache License 2.0 | Compatible with Apache 2.0, MIT, BSD |
| **`pytest`** | `8.3.4` | MIT License | Compatible with all open-source licenses |
| **`bcrypt`** | `4.2.1` | Apache License 2.0 | Compatible with Apache 2.0, MIT, BSD |
| **`rfc8785`** | `0.1.4` | MIT License | Compatible with all open-source licenses |
| **`flake8`** | `7.1.1` | MIT License | Dev tool only (not redistributed) |
| **`bandit`** | `1.8.2` | Apache License 2.0 | Dev tool only (not redistributed) |
| **`pip-audit`** | `2.8.0` | Apache License 2.0 | Dev tool only (not redistributed) |

**Conclusion:** All runtime dependencies are licensed under permissive open-source licenses (Apache 2.0 or MIT). There are zero GPL/copyleft viral constraints inherited from dependencies.

---

## 2. License Options for Repository Owner Selection

The repository owner is invited to select the project license from the following options:

### Option 1: Apache License 2.0 (Recommended for Cloud Security & Enterprise)
- **Strengths:**
  - Includes explicit grant of patent rights from contributors to users.
  - Requires contributors and downstream redistributors to preserve copyright and attribution notices.
  - Protects the project name and trademarks.
  - Highly favored by enterprise cloud security teams and the Apache Software Foundation.
- **Considerations:** Slightly longer legal text; requires NOTICE file if notices are distributed.

### Option 2: MIT License (Currently in Tree)
- **Strengths:**
  - Shortest, most widely recognized permissive license.
  - Maximum developer adoption with minimal friction.
  - Allows both open-source and commercial downstream use with simple attribution.
- **Considerations:** Does not include explicit patent grants or trademark protection clauses.

### Option 3: GNU General Public License v3.0 (GPLv3) (Strong Copyleft)
- **Strengths:**
  - Guarantees that any derivative work or modification must also be released as open source under GPLv3.
  - Prevents proprietary commercial forks without source disclosure.
- **Considerations:** Can discourage adoption by commercial enterprise security teams who prefer permissive licenses.

---

## 3. Action Required from Repository Owner

Please review the options above and confirm your preferred license choice:
1. **Confirm MIT License** (retaining existing `LICENSE` file).
2. **Upgrade to Apache License 2.0** (recommended for patent protection and enterprise adoption).
3. **Select Alternative License** (e.g., AGPLv3 for network-copyleft or BSD 3-Clause).

The agent will NOT modify the existing license text until your explicit choice is communicated.
