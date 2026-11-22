# ExposureFence — Software License Selection & Attribution Analysis

**Document Purpose:** In accordance with open-source release protocols, this document presents the legal and architectural implications of software licenses for ExposureFence.  
**Decision Authority:** Repository Owner (NAENSTUDIOS).  
**Status:** **PENDING REPOSITORY OWNER DECISION.**  

---

## 1. Third-Party Dependency License & Attribution Audit

ExposureFence relies on standard open-source Python libraries. An audit of their respective licenses confirms compatibility with standard permissive open-source distribution:

| Dependency | Declared Version (requirements.txt) | Declared Metadata License | Distribution Compatibility Notes |
| :--- | :--- | :--- | :--- |
| **`boto3`** | `1.36.0` | Apache License 2.0 | Compatible with Apache 2.0, MIT, BSD |
| **`botocore`** | `1.36.0` | Apache License 2.0 | Compatible with Apache 2.0, MIT, BSD |
| **`pytest`** | `8.3.4` | MIT License | Compatible with all open-source licenses |
| **`bcrypt`** | `4.2.1` | Apache License 2.0 | Compatible with Apache 2.0, MIT, BSD |
| **`rfc8785`** | `0.1.4` | Apache Software License (per PyPI classifier metadata) | Compatible with Apache 2.0, MIT, BSD |
| **`flake8`** | `7.1.1` | MIT License | Dev tool only (not redistributed) |
| **`bandit`** | `1.8.2` | Apache License 2.0 | Dev tool only (not redistributed) |
| **`pip-audit`** | `2.8.0` | Apache License 2.0 | Dev tool only (not redistributed) |

> **Note on Dependency Metadata vs. Legal Review:** The licenses listed above are based on declared PyPI distribution metadata and Trove classifiers from installed packages. Package metadata provides helpful developer guidance, but inspection of package metadata alone does not constitute a formal legal audit of full upstream source repositories or transitive dependency licenses.

**Preliminary Assessment:** Based on declared package metadata, all direct runtime dependencies indicate permissive open-source licenses (Apache 2.0 or MIT), with no apparent GPL/copyleft viral constraints inherited from direct dependencies.

---

## 2. License Options for Repository Owner Selection

The repository owner is invited to select the project license from the following options:

### Option 1: Apache License 2.0
- **Characteristics & Permissions:**
  - Grants copyright and express patent permissions from contributors to downstream users, subject to the license terms and conditions.
  - Requires contributors and downstream redistributors to preserve copyright, patent, trademark, and attribution notices from the source.
  - Requires state changes to modified files to be explicitly documented.
  - **Trademark Exclusion:** Section 6 explicitly clarifies that the license does **not** grant trademark rights or permission to use the trade names, trademarks, or service marks of the Licensor (except for reasonable and customary use in describing the origin of the work). It does not create or grant trademark ownership or trademark protection; it simply withholds trademark rights from the scope of copyright/patent permissions.
- **Considerations:** Slightly longer legal text; requires inclusion of the Apache-2.0 license text and preservation of any upstream `NOTICE` file in redistributions.

### Option 2: MIT License (Currently in Tree)
- **Characteristics & Permissions:**
  - Short, permissive, and universally recognized open-source license.
  - Grants broad copyright permissions to use, copy, modify, merge, publish, distribute, sublicense, and sell copies, subject only to retaining the copyright notice and permission notice.
  - Silent on express patent grants and trademark permissions.
- **Considerations:** Does not contain an express patent grant or an explicit trademark exclusion clause.

### Option 3: GNU General Public License v3.0 (GPLv3) (Strong Copyleft)
- **Characteristics & Permissions:**
  - Reciprocal (copyleft) license ensuring that downstream derivative works or modifications remain open source under GPLv3.
  - Includes explicit patent protection and anti-tivoization clauses.
- **Considerations:** Can discourage adoption by commercial enterprise security teams who require permissive licenses for internal or proprietary integrations.

---

## 3. Action Required from Repository Owner

Please review the options above and confirm your preferred license choice:
1. **Confirm MIT License** (retaining existing `LICENSE` file).
2. **Select Apache License 2.0** (subject to owner preference for express patent grant and trademark reservation terms).
3. **Select Alternative License** (e.g., AGPLv3 for network-copyleft or BSD 3-Clause).

The agent will NOT modify the existing license text until your explicit choice is communicated.
