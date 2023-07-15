#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5324. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170485);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2022-2873",
    "CVE-2022-3545",
    "CVE-2022-3623",
    "CVE-2022-4696",
    "CVE-2022-36280",
    "CVE-2022-41218",
    "CVE-2022-45934",
    "CVE-2022-47929",
    "CVE-2023-0179",
    "CVE-2023-0266",
    "CVE-2023-0394",
    "CVE-2023-23454",
    "CVE-2023-23455"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Debian DSA-5324-1 : linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5324 advisory.

  - An out-of-bounds memory access flaw was found in the Linux kernel Intel's iSMT SMBus host controller
    driver in the way a user triggers the I2C_SMBUS_BLOCK_DATA (with the ioctl I2C_SMBUS) with malicious input
    data. This flaw allows a local user to crash the system. (CVE-2022-2873)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function follow_page_pte of the file mm/gup.c of the component BPF. The manipulation
    leads to race condition. The attack can be launched remotely. It is recommended to apply a patch to fix
    this issue. The identifier VDB-211921 was assigned to this vulnerability. (CVE-2022-3623)

  - An out-of-bounds(OOB) memory access vulnerability was found in vmwgfx driver in
    drivers/gpu/vmxgfx/vmxgfx_kms.c in GPU component in the Linux kernel with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-36280)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c
    has an integer wraparound via L2CAP_CONF_REQ packets. (CVE-2022-45934)

  - There exists a use-after-free vulnerability in the Linux kernel through io_uring and the IORING_OP_SPLICE
    operation. If IORING_OP_SPLICE is missing the IO_WQ_WORK_FILES flag, which signals that the operation
    won't use current->nsproxy, so its reference counter is not increased. This assumption is not always true
    as calling io_splice on specific files will call the get_uts function which will use current->nsproxy
    leading to invalidly decreasing its reference counter later causing the use-after-free vulnerability. We
    recommend upgrading to version 5.10.160 or above (CVE-2022-4696)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with tc qdisc and tc class commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

  - Netfilter vulnerability disclosure [fedora-all] (CVE-2023-0179)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5324");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2873");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36280");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4696");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47929");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0179");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0266");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0394");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23455");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.162-1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3623");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0266");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-18-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-18-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'bpftool', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'hyperv-daemons', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'libcpupower-dev', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'libcpupower1', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-arm', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-s390', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-x86', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-cpupower', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-doc', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-4kc-malta', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-4kc-malta', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-5kc-malta', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-686', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-686-pae', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-amd64', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-arm64', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-armmp', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-armmp-lpae', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-cloud-amd64', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-cloud-arm64', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-common', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-common-rt', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-loongson-3', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-marvell', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-octeon', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-powerpc64le', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-rpi', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-rt-686-pae', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-rt-amd64', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-rt-arm64', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-rt-armmp', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-18-s390x', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5kc-malta', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-loongson-3', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-marvell', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-octeon', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-powerpc64le', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rpi', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-headers-s390x', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-4kc-malta', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-4kc-malta-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-5kc-malta', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-5kc-malta-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-686-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-686-pae-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-686-pae-unsigned', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-686-unsigned', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-amd64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-amd64-unsigned', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-arm64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-arm64-unsigned', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-armmp', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-armmp-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-armmp-lpae', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-armmp-lpae-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-cloud-amd64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-cloud-amd64-unsigned', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-cloud-arm64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-cloud-arm64-unsigned', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-loongson-3', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-loongson-3-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-marvell', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-marvell-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-octeon', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-octeon-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-powerpc64le', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-powerpc64le-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rpi', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rpi-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rt-686-pae-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rt-686-pae-unsigned', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rt-amd64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rt-amd64-unsigned', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rt-arm64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rt-arm64-unsigned', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rt-armmp', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-rt-armmp-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-s390x', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-18-s390x-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x-dbg', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-libc-dev', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-perf', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-source', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'linux-support-5.10.0-18', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-armmp-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-marvell-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'usbip', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-s390x-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-octeon-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.162-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-s390x-di', 'reference': '5.10.162-1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'affs-modules-5.10.0-18-4kc-malta-di / etc');
}
