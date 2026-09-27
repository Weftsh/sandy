# Weft Sandboxes host AMI: Amazon Linux 2023 (x86_64, kernel 6.12) with
# Firecracker and jailer, the guest kernel and guest binaries, the host agent,
# and the systemd units that turn an instance into a sandbox host.
#
#   packer init deploy/packer
#   packer build \
#     -var version=1.2.3 \
#     -var host_agent_path=dist/bin/weft-host-agent -var host_agent_sha256=... \
#     -var guest_init_path=dist/guest/weft-guest-init -var guest_init_sha256=... \
#     -var envd_path=dist/guest/envd -var envd_sha256=... \
#     -var envd_license_path=dist/guest/envd.LICENSE \
#     -var vmlinux_path=dist/guest/vmlinux -var vmlinux_sha256=... \
#     deploy/packer
#
# The release workflow builds the inputs first and passes their SHA-256s; the
# build refuses any input whose hash differs. Firecracker's version and hashes
# are pinned in firecracker.auto.pkrvars.hcl.
#
# The AMI stays private. Sharing it with licensed accounts is done by Weft's
# license service, not by this build.

packer {
  required_version = ">= 1.11.0"
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = "= 1.8.2"
    }
  }
}

locals {
  ami_name = "weft-sandboxes-host-v${var.version}-x86_64"
  common_tags = {
    "Name"               = local.ami_name
    "weft:product"       = "weft-sandboxes"
    "weft:component"     = "host"
    "weft:version"       = var.version
    "weft:git-commit"    = var.git_commit
    "weft:firecracker"   = var.firecracker_version
    "weft:base-ami"      = "{{ .SourceAMI }}"
    "weft:base-ami-name" = "{{ .SourceAMIName }}"
  }
  upload_dir = "/tmp/weft-upload"
}

source "amazon-ebs" "host" {
  region          = var.region
  ami_name        = local.ami_name
  ami_description = "Weft Sandboxes ${var.version} sandbox host (Amazon Linux 2023, Firecracker ${var.firecracker_version})"
  ami_regions     = var.ami_regions
  # Private: no launch permissions are granted here.
  ami_users  = []
  ami_groups = []
  # Unencrypted so the license service can share it; the stack's launch
  # template encrypts every volume at launch.
  encrypt_boot          = false
  force_deregister      = var.force_deregister
  force_delete_snapshot = var.force_deregister
  deprecate_at          = timeadd(timestamp(), "${var.deprecate_after_days * 24}h")

  instance_type               = var.build_instance_type
  subnet_id                   = var.subnet_id
  associate_public_ip_address = var.associate_public_ip_address
  # SSH is used only during the build, from the build runner's address only,
  # and sshd is removed from the image at the end.
  temporary_security_group_source_public_ip = true
  ssh_username                              = "ec2-user"
  ssh_interface                             = var.ssh_interface
  ssh_timeout                               = "10m"

  source_ami_filter {
    filters = {
      name                = var.base_ami_name_filter
      architecture        = "x86_64"
      virtualization-type = "hvm"
      root-device-type    = "ebs"
    }
    owners      = ["amazon"]
    most_recent = true
  }

  # Instances launched from the AMI default to IMDSv2 only.
  imds_support = "v2.0"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  ena_support   = true
  sriov_support = true

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 16
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags            = local.common_tags
  snapshot_tags   = local.common_tags
  run_tags        = merge(local.common_tags, { "Name" = "packer-${local.ami_name}" })
  run_volume_tags = merge(local.common_tags, { "Name" = "packer-${local.ami_name}" })
}

build {
  name    = "weft-host"
  sources = ["source.amazon-ebs.host"]

  provisioner "shell" {
    inline = ["mkdir -p ${local.upload_dir}/bin ${local.upload_dir}/guest ${local.upload_dir}/files/licenses"]
  }

  provisioner "file" {
    source      = var.host_agent_path
    destination = "${local.upload_dir}/bin/weft-host-agent"
  }
  provisioner "file" {
    source      = var.guest_init_path
    destination = "${local.upload_dir}/guest/weft-guest-init"
  }
  provisioner "file" {
    source      = var.envd_path
    destination = "${local.upload_dir}/guest/envd"
  }
  provisioner "file" {
    source      = var.vmlinux_path
    destination = "${local.upload_dir}/guest/vmlinux"
  }
  # Unit files, helper scripts and configuration from this directory.
  provisioner "file" {
    source      = "${path.root}/files/"
    destination = "${local.upload_dir}/files"
  }
  # Licenses and notices for everything the image redistributes.
  provisioner "file" {
    sources = [
      "${path.root}/../../NOTICE",
      "${path.root}/../../LICENSE.md",
      "${path.root}/../../LICENSES/Apache-2.0.txt",
      "${path.root}/../../LICENSES/FSL-1.1-ALv2.md",
      var.envd_license_path,
    ]
    destination = "${local.upload_dir}/files/licenses/"
  }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; sudo -E env {{ .Vars }} {{ .Path }}"
    environment_vars = [
      "WEFT_VERSION=${var.version}",
      "WEFT_GIT_COMMIT=${var.git_commit}",
      "UPLOAD_DIR=${local.upload_dir}",
      "FIRECRACKER_VERSION=${var.firecracker_version}",
      "FIRECRACKER_TGZ_SHA256=${var.firecracker_tgz_sha256}",
      "FIRECRACKER_SHA256=${var.firecracker_sha256}",
      "JAILER_SHA256=${var.jailer_sha256}",
      "HOST_AGENT_SHA256=${var.host_agent_sha256}",
      "GUEST_INIT_SHA256=${var.guest_init_sha256}",
      "ENVD_SHA256=${var.envd_sha256}",
      "VMLINUX_SHA256=${var.vmlinux_sha256}",
    ]
    scripts = [
      "${path.root}/scripts/10-base.sh",
      "${path.root}/scripts/20-firecracker.sh",
      "${path.root}/scripts/30-weft.sh",
      "${path.root}/scripts/40-harden.sh",
    ]
  }

  # Last step: remove sshd (the session running this script survives until
  # it ends) and clean up. Packer then stops the instance through the EC2
  # API and creates the image.
  provisioner "shell" {
    execute_command   = "chmod +x {{ .Path }}; sudo -E env {{ .Vars }} {{ .Path }}"
    environment_vars  = ["UPLOAD_DIR=${local.upload_dir}"]
    script            = "${path.root}/scripts/90-finalize.sh"
    expect_disconnect = true
    skip_clean        = true
  }

  post-processor "manifest" {
    output     = var.manifest_path
    strip_path = true
    custom_data = {
      version     = var.version
      git_commit  = var.git_commit
      firecracker = var.firecracker_version
    }
  }
}
