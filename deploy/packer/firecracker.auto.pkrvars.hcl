# Firecracker release installed on hosts, from
# https://github.com/firecracker-microvm/firecracker/releases/tag/v1.17.0
#
# To upgrade: download firecracker-v<version>-x86_64.tgz and its
# .sha256.txt from the release page, check they agree, and take the two
# binary hashes from SHA256SUMS inside the archive. The build verifies all
# three before installing anything.
firecracker_version    = "1.17.0"
firecracker_tgz_sha256 = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
firecracker_sha256     = "99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5"
jailer_sha256          = "65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f"
