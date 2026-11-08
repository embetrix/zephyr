#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Embetrix Embedded Systems Solutions <ayoub.zaki@embetrix.com>
# SPDX-License-Identifier: Apache-2.0

"""Extract a small reproducible set from pinned NIST internalProjection.json files."""

import argparse
import hashlib
import json
from pathlib import Path

REVISION = "975de31eb83d87039ec88934fdc47d8c312b892d"
SOURCES = {
    "ML-KEM-keyGen-FIPS203": "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
    "ML-KEM-encapDecap-FIPS203": "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f",
    "ML-DSA-keyGen-FIPS204": "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
    "ML-DSA-sigGen-FIPS204": "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22",
    "ML-DSA-sigVer-FIPS204": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
}


def select(source, group):
    tests = group["tests"]
    if "keyGen" in source:
        return [("KEYGEN", tests[0])]
    if group.get("function") == "encapsulation":
        return [("ENCAPSULATE", tests[0])]
    if group.get("function") == "decapsulation":
        return [("DECAPSULATE", next(t for t in tests if t["reason"] == reason))
                for reason in ("valid decapsulation", "modified ciphertext")]
    if group.get("signatureInterface") != "external" or group.get("preHash") != "pure":
        return []
    if "sigGen" in source:
        return [("SIGN", min(tests, key=lambda t: (len(t["message"]), t["tcId"])))]
    reasons = ("valid signature and message - signature should verify successfully",
               "modified message", "modified signature - hint")
    return [("VERIFY", min((t for t in tests if t["reason"] == reason),
                            key=lambda t: (len(t["message"]), t["tcId"]))) for reason in reasons]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Directory of <algorithm>.json input files")
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "src/vectors.h")
    args = parser.parse_args()
    spdx = "SPDX"
    header = ["/*", f" * {spdx}-FileCopyrightText: National Institute of Standards and Technology",
              f" * {spdx}-License-Identifier: NIST-Software", " *",
              f" * NIST ACVP-Server {REVISION}.",
              " * Extracted and reformatted on 2026-11-08 by Embetrix Embedded Systems Solutions.",
              " * Key generation, encapsulation and signing outputs use SHA3-256 digests.",
              " * See LICENSES/NIST-Software.txt for the complete upstream notice.", " */", "",
              "#ifndef TESTS_CRYPTO_LEANCRYPTO_ACVP_VECTORS_H_",
              "#define TESTS_CRYPTO_LEANCRYPTO_ACVP_VECTORS_H_", ""]
    vectors = []
    arrays = {}

    def field(data):
        raw = bytes.fromhex(data)
        if not raw:
            return "{NULL, 0U}"
        if raw not in arrays:
            name = f"data_{len(arrays)}"
            arrays[raw] = name
            header.append(f"static const uint8_t {name}[] = {{")
            for offset in range(0, len(raw), 12):
                header.append("\t" + ", ".join(f"0x{x:02x}" for x in raw[offset:offset + 12]) + ",")
            header.extend(["};", ""])
        name = arrays[raw]
        return "{" + name + f", sizeof({name})" + "}"

    for source, digest in SOURCES.items():
        raw = (args.source / f"{source}.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f"{source}: input differs from pinned NIST revision")
        for group in json.loads(raw)["testGroups"]:
            for operation, test in select(source, group):
                dsa = source.startswith("ML-DSA")
                bits = group["parameterSet"].split("-")[-1]
                seed = test.get("seed", test.get("d", "") + test.get("z", ""))
                fields = {}
                if operation == "KEYGEN":
                    fields = {"seed": seed, "pk": test.get("pk", test.get("ek")),
                              "sk": test.get("sk", test.get("dk"))}
                elif operation == "ENCAPSULATE":
                    fields = {"seed": test["m"], "pk": test["ek"], "ct": test["c"],
                              "ss": test["k"]}
                elif operation == "DECAPSULATE":
                    fields = {"sk": test["dk"], "ct": test["c"], "ss": test["k"]}
                else:
                    fields = {"msg": test["message"], "context": test["context"],
                              "sig": test["signature"]}
                    if operation == "SIGN":
                        fields.update(sk=test["sk"], seed=test.get("rnd", ""))
                    else:
                        fields["pk"] = test["pk"]
                hashed = {"KEYGEN": ("pk", "sk"), "ENCAPSULATE": ("ct",),
                          "SIGN": ("sig",)}.get(operation, ())
                for key in hashed:
                    fields[key] = hashlib.sha3_256(bytes.fromhex(fields[key])).hexdigest()
                label = f"{source} tgId={group['tgId']} tcId={test['tcId']}"
                row = ["\t{", f'\t\t.id = "{label}",', f"\t\t.operation = {operation},",
                       f"\t\t.dsa = {str(dsa).lower()},",
                       f"\t\t.type = LC_{'DILITHIUM' if dsa else 'KYBER'}_{bits},",
                       f"\t\t.valid = {str(test.get('testPassed', True)).lower()},"]
                row += [f"\t\t.{key} = {field(value)}," for key, value in fields.items()]
                vectors.extend(row + ["\t},"])
    header += ["static const struct vector vectors[] = {"] + vectors + ["};", "", "#endif", ""]
    args.output.write_text("\n".join(header))


if __name__ == "__main__":
    main()
