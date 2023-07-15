#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5071-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153178);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-36311",
    "CVE-2021-3612",
    "CVE-2021-3653",
    "CVE-2021-3656",
    "CVE-2021-22543"
  );
  script_xref(name:"USN", value:"5071-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-5071-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5071-1 advisory.

  - A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when
    processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested
    guest (L2). Due to improper validation of the virt_ext field, this issue could allow a malicious L1 to
    disable both VMLOAD/VMSAVE intercepts and VLS (Virtual VMLOAD/VMSAVE) for the L2 guest. As a result, the
    L2 guest would be allowed to read/write physical pages of the host, resulting in a crash of the entire
    system, leak of sensitive data or potential guest-to-host escape. (CVE-2021-3656)

  - An issue was discovered in the Linux kernel before 5.9. arch/x86/kvm/svm/sev.c allows attackers to cause a
    denial of service (soft lockup) by triggering destruction of a large SEV VM (which requires unregistering
    many encrypted regions), aka CID-7be74942f184. (CVE-2020-36311)

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

  - A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when
    processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested
    guest (L2). Due to improper validation of the int_ctl field, this issue could allow a malicious L1 to
    enable AVIC support (Advanced Virtual Interrupt Controller) for the L2 guest. As a result, the L2 guest
    would be allowed to read/write physical pages of the host, resulting in a crash of the entire system, leak
    of sensitive data or potential guest-to-host escape. This flaw affects Linux kernel versions prior to
    5.14-rc7. (CVE-2021-3653)

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5071-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3656");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-cloud-tools-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-headers-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-tools-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-cloud-tools-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-headers-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-tools-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1023-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1046-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1052-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1052-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1054-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1056-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1058-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-84-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-84-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-84-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1023-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1056-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1058-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-84-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-84-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.4-headers-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.4-tools-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4-headers-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4-tools-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-headers-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-tools-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-cloud-tools-5.4.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-headers-5.4.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-tools-5.4.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-cloud-tools-5.4.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-headers-5.4.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-tools-5.4.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1023-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1046-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1052-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1052-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1054-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1056-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1058-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-84-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-84-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-84-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1023-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1046-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1052-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1052-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1054-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1056-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1058-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-84-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-84-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-84-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1023-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1046-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1052-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1052-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1054-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1058-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-84-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-84-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.4.0-1046");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.4.0-1046");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1023-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1046-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1052-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1052-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1054-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1056-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1058-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-84-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-84-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-84-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1023-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1052-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1052-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1054-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1056-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1058-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-84-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-headers-5.4.0-1054");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-tools-5.4.0-1054");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.4.0-1054");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.4.0-1054");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1023-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1046-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1052-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1052-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1054-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1056-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1058-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-84-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-84-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-84-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2020-36311', 'CVE-2021-3612', 'CVE-2021-3653', 'CVE-2021-3656', 'CVE-2021-22543');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5071-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-aws', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-cloud-tools-5.4.0-1056', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-headers-5.4.0-1056', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-tools-5.4.0-1056', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-edge', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-azure', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-cloud-tools-5.4.0-1058', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-headers-5.4.0-1058', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-tools-5.4.0-1058', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-edge', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-gkeop-5.4', 'pkgver': '5.4.0.1023.24~18.04.24'},
    {'osver': '18.04', 'pkgname': 'linux-gcp', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-5.4-headers-5.4.0-1052', 'pkgver': '5.4.0-1052.56~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-5.4-tools-5.4.0-1052', 'pkgver': '5.4.0-1052.56~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-edge', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4', 'pkgver': '5.4.0.1052.55~18.04.17'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-headers-5.4.0-1052', 'pkgver': '5.4.0-1052.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-tools-5.4.0-1052', 'pkgver': '5.4.0-1052.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4', 'pkgver': '5.4.0.1023.24~18.04.24'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-cloud-tools-5.4.0-1023', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-headers-5.4.0-1023', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-source-5.4.0', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-tools-5.4.0-1023', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-edge', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp-edge', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gke-5.4', 'pkgver': '5.4.0.1052.55~18.04.17'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gkeop-5.4', 'pkgver': '5.4.0.1023.24~18.04.24'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-edge', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-edge', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1052.55~18.04.17'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1023.24~18.04.24'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-edge', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp-edge', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gke-5.4', 'pkgver': '5.4.0.1052.55~18.04.17'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gkeop-5.4', 'pkgver': '5.4.0.1023.24~18.04.24'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle-edge', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-oracle', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-headers-5.4.0-1054', 'pkgver': '5.4.0-1054.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-tools-5.4.0-1054', 'pkgver': '5.4.0-1054.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-edge', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-edge', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-edge', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-edge', 'pkgver': '5.4.0.1056.39'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '5.4.0.1058.38'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp-edge', 'pkgver': '5.4.0.1052.38'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gke-5.4', 'pkgver': '5.4.0.1052.55~18.04.17'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gkeop-5.4', 'pkgver': '5.4.0.1023.24~18.04.24'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-edge', 'pkgver': '5.4.0.1054.58~18.04.34'},
    {'osver': '20.04', 'pkgname': 'linux-aws-cloud-tools-5.4.0-1056', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-aws-headers-5.4.0-1056', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-aws-lts-20.04', 'pkgver': '5.4.0.1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-aws-tools-5.4.0-1056', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-azure-cloud-tools-5.4.0-1058', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-azure-headers-5.4.0-1058', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-azure-lts-20.04', 'pkgver': '5.4.0.1058.56'},
    {'osver': '20.04', 'pkgname': 'linux-azure-tools-5.4.0-1058', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1046-kvm', 'pkgver': '5.4.0-1046.48'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-84-generic', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-84-generic-lpae', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-84-lowlatency', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-84', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-84-generic', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-84-lowlatency', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure-lts-20.04', 'pkgver': '5.4.0.1058.56'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-gkeop', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-gkeop-5.4', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-headers-5.4.0-1052', 'pkgver': '5.4.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-lts-20.04', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-tools-5.4.0-1052', 'pkgver': '5.4.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-generic', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-gke', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-gke-5.4', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-gke-headers-5.4.0-1052', 'pkgver': '5.4.0-1052.55'},
    {'osver': '20.04', 'pkgname': 'linux-gke-tools-5.4.0-1052', 'pkgver': '5.4.0-1052.55'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-5.4', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-cloud-tools-5.4.0-1023', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-headers-5.4.0-1023', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-source-5.4.0', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-tools-5.4.0-1023', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1046-kvm', 'pkgver': '5.4.0-1046.48'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-84', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-84-generic', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-84-generic-lpae', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-84-lowlatency', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws-lts-20.04', 'pkgver': '5.4.0.1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure-lts-20.04', 'pkgver': '5.4.0.1058.56'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gcp-lts-20.04', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gke', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gke-5.4', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gkeop', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gkeop-5.4', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.4.0.1046.45'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle-lts-20.04', 'pkgver': '5.4.0.1054.54'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1046-kvm', 'pkgver': '5.4.0-1046.48'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-84-generic', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-84-generic-lpae', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-84-lowlatency', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws-lts-20.04', 'pkgver': '5.4.0.1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-lts-20.04', 'pkgver': '5.4.0.1058.56'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp-lts-20.04', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.4.0.1046.45'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle-lts-20.04', 'pkgver': '5.4.0.1054.54'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1046-kvm', 'pkgver': '5.4.0-1046.48'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-84-generic', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-84-lowlatency', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-kvm', 'pkgver': '5.4.0.1046.45'},
    {'osver': '20.04', 'pkgname': 'linux-kvm-headers-5.4.0-1046', 'pkgver': '5.4.0-1046.48'},
    {'osver': '20.04', 'pkgname': 'linux-kvm-tools-5.4.0-1046', 'pkgver': '5.4.0-1046.48'},
    {'osver': '20.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1046-kvm', 'pkgver': '5.4.0-1046.48'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-84-generic', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-84-generic-lpae', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-84-lowlatency', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-84-generic', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws-lts-20.04', 'pkgver': '5.4.0.1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure-lts-20.04', 'pkgver': '5.4.0.1058.56'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gcp-lts-20.04', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gke-5.4', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gkeop', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gkeop-5.4', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1-tools-host', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-oem-tools-host', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-headers-5.4.0-1054', 'pkgver': '5.4.0-1054.58'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-lts-20.04', 'pkgver': '5.4.0.1054.54'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-tools-5.4.0-1054', 'pkgver': '5.4.0-1054.58'},
    {'osver': '20.04', 'pkgname': 'linux-source', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-source-5.4.0', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1023-gkeop', 'pkgver': '5.4.0-1023.24'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1046-kvm', 'pkgver': '5.4.0-1046.48'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1052-gcp', 'pkgver': '5.4.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1052-gke', 'pkgver': '5.4.0-1052.55'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1054-oracle', 'pkgver': '5.4.0-1054.58'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1056-aws', 'pkgver': '5.4.0-1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1058-azure', 'pkgver': '5.4.0-1058.60'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-84', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-84-generic', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-84-generic-lpae', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-84-lowlatency', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws-lts-20.04', 'pkgver': '5.4.0.1056.59'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure-lts-20.04', 'pkgver': '5.4.0.1058.56'},
    {'osver': '20.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gcp-lts-20.04', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gke', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gke-5.4', 'pkgver': '5.4.0.1052.62'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gkeop', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gkeop-5.4', 'pkgver': '5.4.0.1023.26'},
    {'osver': '20.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.4.0-84.94'},
    {'osver': '20.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.4.0.1046.45'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle-lts-20.04', 'pkgver': '5.4.0.1054.54'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-virtual', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.84.88'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.84.88'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-5.4-cloud-tools-5.4.0-1056 / etc');
}
