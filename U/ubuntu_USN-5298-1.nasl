#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5298-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158249);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-4083",
    "CVE-2021-4155",
    "CVE-2021-4202",
    "CVE-2021-22600",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715",
    "CVE-2021-39685",
    "CVE-2022-0330",
    "CVE-2022-22942"
  );
  script_xref(name:"USN", value:"5298-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-5298-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5298-1 advisory.

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through
    crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected
    versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755 (CVE-2021-22600)

  - Rogue backends can cause DoS of guests via high frequency events T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen offers the
    ability to run PV backends in regular unprivileged guests, typically referred to as driver domains.
    Running PV backends in driver domains has one primary security advantage: if a driver domain gets
    compromised, it doesn't have the privileges to take over the system. However, a malicious driver domain
    could try to attack other guests via sending events at a high frequency leading to a Denial of Service in
    the guest due to trying to service interrupts for elongated amounts of time. There are three affected
    backends: * blkfront patch 1, CVE-2021-28711 * netfront patch 2, CVE-2021-28712 * hvc_xen (console) patch
    3, CVE-2021-28713 (CVE-2021-28711, CVE-2021-28712, CVE-2021-28713)

  - Guest can force Linux netback driver to hog large amounts of kernel memory T[his CNA information record
    relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.]
    Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is
    ready to process them. There are some measures taken for avoiding to pile up too much data, but those can
    be bypassed by the guest: There is a timeout how long the client side of an interface can stop consuming
    new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default).
    Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time.
    (CVE-2021-28715) The timeout could even never trigger if the guest manages to have only one free slot in
    its RX queue ring page and the next package would require more than one free slot, which may be the case
    when using GSO, XDP, or software hashing. (CVE-2021-28714) (CVE-2021-28714, CVE-2021-28715)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5298-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39685");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0330");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.15.0-1121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.15.0-1120");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.15.0-1121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-cloud-tools-4.15.0-1120");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-tools-4.15.0-1120");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.15.0-1121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-cloud-tools-4.15.0-1131");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-headers-4.15.0-1131");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-tools-4.15.0-1131");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-4.15.0-1131");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-4.15.0-1131");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-4.15.0-1131");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1035-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1087-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1107-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1116-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1120-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1120-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1121-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1131-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-169-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-169-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-169-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1120-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1121-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1131-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-169-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-169-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x-headers-4.15.0-1035");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x-tools-4.15.0-1035");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-headers-4.15.0-1116");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-tools-4.15.0-1116");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-4.15.0-1116");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-4.15.0-1116");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1035-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1087-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1107-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1116-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1120-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1120-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1121-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1131-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-169-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-169-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-169-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-cloud-tools-4.15.0-169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-tools-4.15.0-169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1035-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1087-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1107-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1116-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1120-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1131-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-169-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-169-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-169-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1035-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1087-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1116-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1120-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1121-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1131-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-169-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-169-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.15.0-1107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.15.0-1107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1035-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1087-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1107-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1116-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1120-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1120-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1121-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1131-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-169-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-169-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-169-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1087-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1116-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1120-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1121-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1131-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-169-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-4.15.0-1087");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-4.15.0-1087");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-headers-4.15.0-1120");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-tools-4.15.0-1120");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.15.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1035-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1087-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1107-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1116-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1120-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1120-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1121-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1131-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-169-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-169-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-169-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04-edge");
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
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-aws-edge', 'pkgver': '4.15.0.1120.111'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.15.0-1120', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe', 'pkgver': '4.15.0.1120.111'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-cloud-tools-4.15.0-1120', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-tools-4.15.0-1120', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-azure-cloud-tools-4.15.0-1131', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure-edge', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-azure-headers-4.15.0-1131', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure-tools-4.15.0-1131', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1120-aws', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-169-generic', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-1120-aws', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-169-generic', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-gcp', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-gcp-headers-4.15.0-1116', 'pkgver': '4.15.0-1116.130~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-gcp-tools-4.15.0-1116', 'pkgver': '4.15.0-1116.130~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-gke', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1120-aws', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-169', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-169-generic', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws-hwe', 'pkgver': '4.15.0.1120.111'},
    {'osver': '16.04', 'pkgname': 'linux-headers-azure', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-headers-gke', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oem', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '4.15.0.1087.75'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-cloud-tools-4.15.0-169', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-tools-4.15.0-169', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-169-generic', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws-hwe', 'pkgver': '4.15.0.1120.111'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-image-gcp', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-image-gke', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-image-oracle', 'pkgver': '4.15.0.1087.75'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1120-aws', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-169-generic', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1120-aws', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-169-generic', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1120-aws', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-169-generic', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws-hwe', 'pkgver': '4.15.0.1120.111'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-oem', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-oracle', 'pkgver': '4.15.0.1087.75'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-headers-4.15.0-1087', 'pkgver': '4.15.0-1087.95~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-tools-4.15.0-1087', 'pkgver': '4.15.0-1087.95~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-signed-azure', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oem', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '4.15.0.1087.75'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oem', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '4.15.0.1087.75'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1120-aws', 'pkgver': '4.15.0-1120.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-169-generic', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws-hwe', 'pkgver': '4.15.0.1120.111'},
    {'osver': '16.04', 'pkgname': 'linux-tools-azure', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '4.15.0.1131.122'},
    {'osver': '16.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-tools-gke', 'pkgver': '4.15.0.1116.117'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oem', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '4.15.0.1087.75'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.169.161'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.161'},
    {'osver': '18.04', 'pkgname': 'linux-aws-cloud-tools-4.15.0-1121', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-aws-headers-4.15.0-1121', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-aws-lts-18.04', 'pkgver': '4.15.0.1121.124'},
    {'osver': '18.04', 'pkgname': 'linux-aws-tools-4.15.0-1121', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-cloud-tools-4.15.0-1131', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-headers-4.15.0-1131', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-tools-4.15.0-1131', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-azure-lts-18.04', 'pkgver': '4.15.0.1131.104'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1035-dell300x', 'pkgver': '4.15.0-1035.40'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1107-kvm', 'pkgver': '4.15.0-1107.109'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1120-snapdragon', 'pkgver': '4.15.0-1120.129'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1121-aws', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-169-generic', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-169-generic-lpae', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1121-aws', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-169', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-169-generic', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-lts-18.04', 'pkgver': '4.15.0.1131.104'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x', 'pkgver': '4.15.0.1035.37'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x-headers-4.15.0-1035', 'pkgver': '4.15.0-1035.40'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x-tools-4.15.0-1035', 'pkgver': '4.15.0-1035.40'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-headers-4.15.0-1116', 'pkgver': '4.15.0-1116.130'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-tools-4.15.0-1116', 'pkgver': '4.15.0-1116.130'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-lts-18.04', 'pkgver': '4.15.0.1116.135'},
    {'osver': '18.04', 'pkgname': 'linux-generic', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1035-dell300x', 'pkgver': '4.15.0-1035.40'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1107-kvm', 'pkgver': '4.15.0-1107.109'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1120-snapdragon', 'pkgver': '4.15.0-1120.129'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1121-aws', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-169', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-169-generic', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-169-generic-lpae', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-lts-18.04', 'pkgver': '4.15.0.1121.124'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-lts-18.04', 'pkgver': '4.15.0.1131.104'},
    {'osver': '18.04', 'pkgname': 'linux-headers-dell300x', 'pkgver': '4.15.0.1035.37'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp-lts-18.04', 'pkgver': '4.15.0.1116.135'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.15.0.1107.103'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-lts-18.04', 'pkgver': '4.15.0.1087.97'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon', 'pkgver': '4.15.0.1120.123'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1035-dell300x', 'pkgver': '4.15.0-1035.40'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1107-kvm', 'pkgver': '4.15.0-1107.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1120-snapdragon', 'pkgver': '4.15.0-1120.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-169-generic', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-169-generic-lpae', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-lts-18.04', 'pkgver': '4.15.0.1121.124'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-lts-18.04', 'pkgver': '4.15.0.1131.104'},
    {'osver': '18.04', 'pkgname': 'linux-image-dell300x', 'pkgver': '4.15.0.1035.37'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-lts-18.04', 'pkgver': '4.15.0.1116.135'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.15.0.1107.103'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-lts-18.04', 'pkgver': '4.15.0.1087.97'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.15.0.1120.123'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1035-dell300x', 'pkgver': '4.15.0-1035.40'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1121-aws', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-169-generic', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-kvm', 'pkgver': '4.15.0.1107.103'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-headers-4.15.0-1107', 'pkgver': '4.15.0-1107.109'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-tools-4.15.0-1107', 'pkgver': '4.15.0-1107.109'},
    {'osver': '18.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1035-dell300x', 'pkgver': '4.15.0-1035.40'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1107-kvm', 'pkgver': '4.15.0-1107.109'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1120-snapdragon', 'pkgver': '4.15.0-1120.129'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1121-aws', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-169-generic', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-169-generic-lpae', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1121-aws', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-169-generic', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-lts-18.04', 'pkgver': '4.15.0.1121.124'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-lts-18.04', 'pkgver': '4.15.0.1131.104'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp-lts-18.04', 'pkgver': '4.15.0.1116.135'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-headers-4.15.0-1087', 'pkgver': '4.15.0-1087.95'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-lts-18.04', 'pkgver': '4.15.0.1087.97'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-tools-4.15.0-1087', 'pkgver': '4.15.0-1087.95'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-lts-18.04', 'pkgver': '4.15.0.1131.104'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-lts-18.04', 'pkgver': '4.15.0.1131.104'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-lts-18.04', 'pkgver': '4.15.0.1087.97'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-lts-18.04', 'pkgver': '4.15.0.1087.97'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon', 'pkgver': '4.15.0.1120.123'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-headers-4.15.0-1120', 'pkgver': '4.15.0-1120.129'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-tools-4.15.0-1120', 'pkgver': '4.15.0-1120.129'},
    {'osver': '18.04', 'pkgname': 'linux-source', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1035-dell300x', 'pkgver': '4.15.0-1035.40'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1087-oracle', 'pkgver': '4.15.0-1087.95'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1107-kvm', 'pkgver': '4.15.0-1107.109'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1116-gcp', 'pkgver': '4.15.0-1116.130'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1120-snapdragon', 'pkgver': '4.15.0-1120.129'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1121-aws', 'pkgver': '4.15.0-1121.129'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1131-azure', 'pkgver': '4.15.0-1131.144'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-169', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-169-generic', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-169-generic-lpae', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-169-lowlatency', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-lts-18.04', 'pkgver': '4.15.0.1121.124'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-lts-18.04', 'pkgver': '4.15.0.1131.104'},
    {'osver': '18.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-tools-dell300x', 'pkgver': '4.15.0.1035.37'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp-lts-18.04', 'pkgver': '4.15.0.1116.135'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.15.0-169.177'},
    {'osver': '18.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.15.0.1107.103'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-lts-18.04', 'pkgver': '4.15.0.1087.97'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon', 'pkgver': '4.15.0.1120.123'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-virtual', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.169.158'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.169.158'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws-cloud-tools-4.15.0-1121 / linux-aws-edge / etc');
}
