variable "version" {
  type        = string
  description = "Weft Sandboxes release version (without the leading v)."
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?$", var.version))
    error_message = "The version must look like 1.2.3 or 1.2.3-rc.1."
  }
}

variable "git_commit" {
  type        = string
  default     = "unknown"
  description = "Commit the release was built from (recorded as a tag and in /opt/weft/MANIFEST)."
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Region the AMI is built in."
}

variable "ami_regions" {
  type        = list(string)
  default     = []
  description = "Additional Regions to copy the finished AMI to (the copies stay private)."
}

variable "force_deregister" {
  type        = bool
  default     = false
  description = "Replace an existing AMI with the same name (only for re-running a failed release)."
}

variable "deprecate_after_days" {
  type        = number
  default     = 730
  description = "Mark the AMI deprecated after this many days."
}

variable "build_instance_type" {
  type        = string
  default     = "m7i.large"
  description = "Instance type used to build the image (x86_64; no KVM needed during the build)."
}

variable "subnet_id" {
  type        = string
  default     = null
  description = "Subnet for the build instance. Defaults to the default VPC."
}

variable "associate_public_ip_address" {
  type        = bool
  default     = true
  description = "Give the build instance a public IP (needed with ssh_interface=public_ip)."
}

variable "ssh_interface" {
  type        = string
  default     = "public_ip"
  description = "How Packer reaches the build instance: public_ip, private_ip or session_manager."
  validation {
    condition     = contains(["public_ip", "private_ip", "session_manager"], var.ssh_interface)
    error_message = "The ssh_interface value must be public_ip, private_ip or session_manager."
  }
}

variable "base_ami_name_filter" {
  type        = string
  default     = "al2023-ami-2023.*-kernel-6.12-x86_64"
  description = "Amazon Linux 2023 AMI name filter (owner amazon, newest match)."
}

variable "manifest_path" {
  type        = string
  default     = "packer-manifest.json"
  description = "Where the manifest post-processor writes the AMI IDs per Region."
}

# --- Build inputs (produced earlier in the release workflow) ----------------

variable "host_agent_path" {
  type        = string
  description = "weft-host-agent binary (x86_64, built for Amazon Linux 2023)."
}

variable "host_agent_sha256" {
  type        = string
  description = "SHA-256 of host_agent_path."
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.host_agent_sha256))
    error_message = "The host_agent_sha256 value must be 64 lowercase hex characters."
  }
}

variable "guest_init_path" {
  type        = string
  description = "weft-guest-init binary (static musl)."
}

variable "guest_init_sha256" {
  type        = string
  description = "SHA-256 of guest_init_path."
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.guest_init_sha256))
    error_message = "The guest_init_sha256 value must be 64 lowercase hex characters."
  }
}

variable "envd_path" {
  type        = string
  description = "envd binary built by guest/envd/build.sh (which verifies its own pinned hash)."
}

variable "envd_sha256" {
  type        = string
  description = "SHA-256 of envd_path."
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.envd_sha256))
    error_message = "The envd_sha256 value must be 64 lowercase hex characters."
  }
}

variable "envd_license_path" {
  type        = string
  description = "envd's Apache-2.0 license (envd.LICENSE, written next to envd by guest/envd/build.sh)."
}

variable "vmlinux_path" {
  type        = string
  description = "Uncompressed guest kernel built by guest/kernel/build.sh."
}

variable "vmlinux_sha256" {
  type        = string
  description = "SHA-256 of vmlinux_path."
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.vmlinux_sha256))
    error_message = "The vmlinux_sha256 value must be 64 lowercase hex characters."
  }
}

# --- Firecracker (pinned in firecracker.auto.pkrvars.hcl) -------------------

variable "firecracker_version" {
  type        = string
  description = "Firecracker release (without the leading v)."
}

variable "firecracker_tgz_sha256" {
  type        = string
  description = "SHA-256 of firecracker-v<version>-x86_64.tgz from the official GitHub release."
}

variable "firecracker_sha256" {
  type        = string
  description = "SHA-256 of the firecracker binary inside the release archive."
}

variable "jailer_sha256" {
  type        = string
  description = "SHA-256 of the jailer binary inside the release archive."
}
