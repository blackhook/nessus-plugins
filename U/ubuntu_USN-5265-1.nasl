#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5265-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157351);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2020-27820",
    "CVE-2021-3640",
    "CVE-2021-3752",
    "CVE-2021-3772",
    "CVE-2021-4001",
    "CVE-2021-4090",
    "CVE-2021-4093",
    "CVE-2021-4202",
    "CVE-2021-42327",
    "CVE-2021-42739"
  );
  script_xref(name:"USN", value:"5265-1");

  script_name(english:"Ubuntu 20.04 LTS / 21.10 : Linux kernel vulnerabilities (USN-5265-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 21.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5265-1 advisory.

  - A race condition was found in the Linux kernel's ebpf verifier between bpf_map_update_elem and
    bpf_map_freeze due to a missing lock in kernel/bpf/syscall.c. In this flaw, a local user with a special
    privilege (cap_sys_admin or cap_bpf) can modify the frozen mapped address space. This flaw affects kernel
    versions prior to 5.16 rc2. (CVE-2021-4001)

  - A vulnerability was found in Linux kernel, where a use-after-frees in nouveau's postclose() handler could
    happen if removing device (that is not common to remove video card physically without power-off, but same
    happens if unbind the driver). (CVE-2020-27820)

  - A use-after-free flaw was found in the Linux kernel's Bluetooth subsystem in the way user calls connect to
    the socket and disconnect simultaneously due to a race condition. This flaw allows a user to crash the
    system or escalate their privileges. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-3752)

  - An out-of-bounds (OOB) memory write flaw was found in the NFSD in the Linux kernel. Missing sanity may
    lead to a write beyond bmval[bmlen-1] in nfsd4_decode_bitmap4 in fs/nfsd/nfs4xdr.c. In this flaw, a local
    attacker with user privilege may gain access to out-of-bounds memory, leading to a system integrity and
    confidentiality threat. (CVE-2021-4090)

  - A flaw was found in the KVM's AMD code for supporting the Secure Encrypted Virtualization-Encrypted State
    (SEV-ES). A KVM guest using SEV-ES can trigger out-of-bounds reads and writes in the host kernel via a
    malicious VMGEXIT for a string I/O instruction (for example, outs or ins) using the exit reason
    SVM_EXIT_IOIO. This issue results in a crash of the entire system or a potential guest-to-host escape
    scenario. (CVE-2021-4093)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5265-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4093");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.11-cloud-tools-5.11.0-1028");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.11-headers-5.11.0-1028");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.11-tools-5.11.0-1028");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.13-cloud-tools-5.13.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.13-headers-5.13.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.13-tools-5.13.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.13.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.13.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.13.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1028-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1028-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1029-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1011-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1012-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1013-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1016-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1016-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1016-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1029-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-28-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-28-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-28-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-28-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-1028-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-1012-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-28-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-28-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.11-headers-5.11.0-1029");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.11-tools-5.11.0-1029");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.13.0-1013");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.13.0-1013");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1028-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1028-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1029-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1011-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1012-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1013-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1016-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1016-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1016-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1029-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-28-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-28-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-28-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-28-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-cloud-tools-5.13.0-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-headers-5.13.0-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-source-5.13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-tools-5.13.0-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1028-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1029-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1011-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1012-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1013-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1016-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1016-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1016-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1029-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-28-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-28-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-28-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-28-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1028-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1028-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1029-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1011-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1012-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1013-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1016-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1029-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-28-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-28-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-28-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.13.0-1011");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.13.0-1011");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1028-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1028-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1029-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1011-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1012-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1013-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1016-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1016-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1016-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1029-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-28-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-28-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-28-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-28-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1028-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1028-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1029-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1012-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1013-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1016-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1016-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1016-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-28-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.13-headers-5.13.0-1029");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.13-tools-5.13.0-1029");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.13-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.11-headers-5.11.0-1028");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.11-tools-5.11.0-1028");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.13.0-1016");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.13.0-1016");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.13.0-1016");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.13.0-1016");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1028-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1028-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1029-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1011-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1012-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1013-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1016-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1016-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1016-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1029-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-28-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-28-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-28-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-28-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-aws', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.11-cloud-tools-5.11.0-1028', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.11-headers-5.11.0-1028', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.11-tools-5.11.0-1028', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.13-cloud-tools-5.13.0-1012', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.13-headers-5.13.0-1012', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.13-tools-5.13.0-1012', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-aws-edge', 'pkgver': '5.13.0.1012.13~20.04.4'},
    {'osver': '20.04', 'pkgname': 'linux-azure', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.11-cloud-tools-5.11.0-1028', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.11-headers-5.11.0-1028', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.11-tools-5.11.0-1028', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1028-aws', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1028-azure', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1028-oracle', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1029-gcp', 'pkgver': '5.11.0-1029.33~20.04.3'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-1029-oem', 'pkgver': '5.13.0-1029.36'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-28-generic', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-1028-aws', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-1028-azure', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.13.0-28-generic', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-gcp', 'pkgver': '5.11.0.1029.33~20.04.27'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-5.11-headers-5.11.0-1029', 'pkgver': '5.11.0-1029.33~20.04.3'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-5.11-tools-5.11.0-1029', 'pkgver': '5.11.0-1029.33~20.04.3'},
    {'osver': '20.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1028-aws', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1028-azure', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1028-oracle', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1029-gcp', 'pkgver': '5.11.0-1029.33~20.04.3'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-1029-oem', 'pkgver': '5.13.0-1029.36'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-28-generic', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws-edge', 'pkgver': '5.13.0.1012.13~20.04.4'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.11.0.1029.33~20.04.27'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04c', 'pkgver': '5.13.0.1029.31'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.11.0.1028.31~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-cloud-tools-5.13.0-28', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-cloud-tools-common', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-headers-5.13.0-28', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-source-5.13.0', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-tools-5.13.0-28', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-tools-common', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-tools-host', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1028-azure', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1028-oracle', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1029-gcp', 'pkgver': '5.11.0-1029.33~20.04.3'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-1029-oem', 'pkgver': '5.13.0-1029.36'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-28-generic', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.13.0.1012.13~20.04.4'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.11.0.1029.33~20.04.27'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04c', 'pkgver': '5.13.0.1029.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.11.0.1028.31~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1028-aws', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1028-azure', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1028-oracle', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1029-gcp', 'pkgver': '5.11.0-1029.33~20.04.3'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-1029-oem', 'pkgver': '5.13.0-1029.36'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-28-generic', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1028-aws', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1028-azure', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1028-oracle', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1029-gcp', 'pkgver': '5.11.0-1029.33~20.04.3'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-1029-oem', 'pkgver': '5.13.0-1029.36'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-28-generic', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1028-aws', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1028-azure', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1028-oracle', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1029-gcp', 'pkgver': '5.11.0-1029.33~20.04.3'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.13.0-28-generic', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws-edge', 'pkgver': '5.13.0.1012.13~20.04.4'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.11.0.1029.33~20.04.27'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04c', 'pkgver': '5.13.0.1029.31'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.13-headers-5.13.0-1029', 'pkgver': '5.13.0-1029.36'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.13-tools-5.13.0-1029', 'pkgver': '5.13.0-1029.36'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.13-tools-host', 'pkgver': '5.13.0-1029.36'},
    {'osver': '20.04', 'pkgname': 'linux-oracle', 'pkgver': '5.11.0.1028.31~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-5.11-headers-5.11.0-1028', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-5.11-tools-5.11.0-1028', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1028-aws', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1028-azure', 'pkgver': '5.11.0-1028.31~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1028-oracle', 'pkgver': '5.11.0-1028.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1029-gcp', 'pkgver': '5.11.0-1029.33~20.04.3'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-1029-oem', 'pkgver': '5.13.0-1029.36'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-28-generic', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws-edge', 'pkgver': '5.13.0.1012.13~20.04.4'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.11.0.1028.31~20.04.26'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.11.0.1029.33~20.04.27'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04c', 'pkgver': '5.13.0.1029.31'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.11.0.1028.31~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.13.0.28.31~20.04.15'},
    {'osver': '21.10', 'pkgname': 'linux-aws', 'pkgver': '5.13.0.1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-aws-cloud-tools-5.13.0-1012', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-aws-headers-5.13.0-1012', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-aws-tools-5.13.0-1012', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1011-kvm', 'pkgver': '5.13.0-1011.12'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1013-gcp', 'pkgver': '5.13.0-1013.16'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1016-oracle', 'pkgver': '5.13.0-1016.20'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1016-raspi', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1016-raspi-nolpae', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-28-generic', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-28', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-28-generic', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-crashdump', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-gcp', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-gcp-headers-5.13.0-1013', 'pkgver': '5.13.0-1013.16'},
    {'osver': '21.10', 'pkgname': 'linux-gcp-tools-5.13.0-1013', 'pkgver': '5.13.0-1013.16'},
    {'osver': '21.10', 'pkgname': 'linux-generic', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-gke', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1011-kvm', 'pkgver': '5.13.0-1011.12'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1013-gcp', 'pkgver': '5.13.0-1013.16'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1016-oracle', 'pkgver': '5.13.0-1016.20'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1016-raspi', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1016-raspi-nolpae', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-28', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-28-generic', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-headers-aws', 'pkgver': '5.13.0.1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-gke', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.13.0.1011.11'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.13.0.1016.16'},
    {'osver': '21.10', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-raspi-nolpae', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1011-kvm', 'pkgver': '5.13.0-1011.12'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1013-gcp', 'pkgver': '5.13.0-1013.16'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1016-oracle', 'pkgver': '5.13.0-1016.20'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1016-raspi', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1016-raspi-nolpae', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-28-generic', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-image-aws', 'pkgver': '5.13.0.1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-gcp', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-gke', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-image-kvm', 'pkgver': '5.13.0.1011.11'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-oracle', 'pkgver': '5.13.0.1016.16'},
    {'osver': '21.10', 'pkgname': 'linux-image-raspi', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1011-kvm', 'pkgver': '5.13.0-1011.12'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1013-gcp', 'pkgver': '5.13.0-1013.16'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1016-oracle', 'pkgver': '5.13.0-1016.20'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-28-generic', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-kvm', 'pkgver': '5.13.0.1011.11'},
    {'osver': '21.10', 'pkgname': 'linux-kvm-headers-5.13.0-1011', 'pkgver': '5.13.0-1011.12'},
    {'osver': '21.10', 'pkgname': 'linux-kvm-tools-5.13.0-1011', 'pkgver': '5.13.0-1011.12'},
    {'osver': '21.10', 'pkgname': 'linux-libc-dev', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1011-kvm', 'pkgver': '5.13.0-1011.12'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1013-gcp', 'pkgver': '5.13.0-1013.16'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1016-oracle', 'pkgver': '5.13.0-1016.20'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1016-raspi', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1016-raspi-nolpae', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-28-generic', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1013-gcp', 'pkgver': '5.13.0-1013.16'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1016-oracle', 'pkgver': '5.13.0-1016.20'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1016-raspi', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1016-raspi-nolpae', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-28-generic', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.13.0.1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-raspi', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-raspi-nolpae', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-oracle', 'pkgver': '5.13.0.1016.16'},
    {'osver': '21.10', 'pkgname': 'linux-oracle-headers-5.13.0-1016', 'pkgver': '5.13.0-1016.20'},
    {'osver': '21.10', 'pkgname': 'linux-oracle-tools-5.13.0-1016', 'pkgver': '5.13.0-1016.20'},
    {'osver': '21.10', 'pkgname': 'linux-raspi', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-raspi-headers-5.13.0-1016', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-raspi-nolpae', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-raspi-tools-5.13.0-1016', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-source', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-source-5.13.0', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1011-kvm', 'pkgver': '5.13.0-1011.12'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1012-aws', 'pkgver': '5.13.0-1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1013-gcp', 'pkgver': '5.13.0-1013.16'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1016-oracle', 'pkgver': '5.13.0-1016.20'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1016-raspi', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1016-raspi-nolpae', 'pkgver': '5.13.0-1016.18'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-28', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-28-generic', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-28-generic-64k', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-28-generic-lpae', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-28-lowlatency', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-tools-aws', 'pkgver': '5.13.0.1012.13'},
    {'osver': '21.10', 'pkgname': 'linux-tools-common', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-gke', 'pkgver': '5.13.0.1013.12'},
    {'osver': '21.10', 'pkgname': 'linux-tools-host', 'pkgver': '5.13.0-28.31'},
    {'osver': '21.10', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.13.0.1011.11'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.13.0.1016.16'},
    {'osver': '21.10', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-raspi-nolpae', 'pkgver': '5.13.0.1016.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-virtual', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.13.0.28.38'},
    {'osver': '21.10', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.28.38'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-5.11-cloud-tools-5.11.0-1028 / etc');
}
