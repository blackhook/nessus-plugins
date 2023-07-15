#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4564. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130982);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/12");

  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-11135");
  script_xref(name:"DSA", value:"4564");

  script_name(english:"Debian DSA-4564-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service, or information
leak.

  - CVE-2018-12207
    It was discovered that on Intel CPUs supporting hardware
    virtualisation with Extended Page Tables (EPT), a guest
    VM may manipulate the memory management hardware to
    cause a Machine Check Error (MCE) and denial of service
    (hang or crash).

  The guest triggers this error by changing page tables without a TLB
  flush, so that both 4 KB and 2 MB entries for the same virtual
  address are loaded into the instruction TLB (iTLB). This update
  implements a mitigation in KVM that prevents guest VMs from loading
  2 MB entries into the iTLB. This will reduce performance of guest
  VMs.

  Further information on the mitigation can be found at or in the
  linux-doc-4.9 or linux-doc-4.19 package.

  A qemu update adding support for the PSCHANGE_MC_NO feature, which
  allows to disable iTLB Multihit mitigations in nested hypervisors
  will be provided via DSA 4566-1.

  Intel's explanation of the issue can be found at.

  - CVE-2019-0154
    Intel discovered that on their 8th and 9th generation
    GPUs, reading certain registers while the GPU is in a
    low-power state can cause a system hang. A local user
    permitted to use the GPU can use this for denial of
    service.

  This update mitigates the issue through changes to the i915 driver.

  The affected chips (gen8 and gen9) are listed at.

  - CVE-2019-0155
    Intel discovered that their 9th generation and newer
    GPUs are missing a security check in the Blitter Command
    Streamer (BCS). A local user permitted to use the GPU
    could use this to access any memory that the GPU has
    access to, which could result in a denial of service
    (memory corruption or crash), a leak of sensitive
    information, or privilege escalation.

  This update mitigates the issue by adding the security check to the
  i915 driver.

  The affected chips (gen9 onward) are listed at.

  - CVE-2019-11135
    It was discovered that on Intel CPUs supporting
    transactional memory (TSX), a transaction that is going
    to be aborted may continue to execute speculatively,
    reading sensitive data from internal buffers and leaking
    it through dependent operations. Intel calls this 'TSX
    Asynchronous Abort' (TAA).

  For CPUs affected by the previously published Microarchitectural
  Data Sampling (MDS) issues (CVE-2018-12126, CVE-2018-12127,
  CVE-2018-12130, CVE-2019-11091 ), the existing mitigation also
  mitigates this issue.

  For processors that are vulnerable to TAA but not MDS, this update
  disables TSX by default. This mitigation requires updated CPU
  microcode. An updated intel-microcode package (only available in
  Debian non-free) will be provided via DSA 4565-1. The updated CPU
  microcode may also be available as part of a system firmware
  ('BIOS') update.

  Further information on the mitigation can be found at or in the
  linux-doc-4.9 or linux-doc-4.19 package.

  Intel's explanation of the issue can be found at."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-12207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-0154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-0155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-12126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-12127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-12130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4564"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 4.9.189-3+deb9u2.

For the stable distribution (buster), these problems have been fixed
in version 4.19.67-2+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dasd-extra-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dasd-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"efi-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fancontrol-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firewire-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firewire-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hyperv-daemons", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hypervisor-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ipv6-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jffs2-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"leds-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"leds-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libbpf-dev", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libbpf4.19", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcpupower-dev", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcpupower1", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"liblockdep-dev", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"liblockdep4.19", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-compiler-gcc-8-arm", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-compiler-gcc-8-s390", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-compiler-gcc-8-x86", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-config-4.19", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-cpupower", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-doc-4.19", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-4kc-malta", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-5kc-malta", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-686", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-686-pae", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-amd64", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-arm64", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-armel", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-armhf", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-i386", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-mips", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-mips64el", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-mipsel", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-ppc64el", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-s390x", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-amd64", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-arm64", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-armmp", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-armmp-lpae", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-cloud-amd64", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-common", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-common-rt", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-loongson-3", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-marvell", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-octeon", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-powerpc64le", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rpi", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-686-pae", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-amd64", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-arm64", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-armmp", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-s390x", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-4kc-malta", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-4kc-malta-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-5kc-malta", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-5kc-malta-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-pae-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-pae-unsigned", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-unsigned", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-amd64-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-amd64-unsigned", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-arm64-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-arm64-unsigned", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp-lpae", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp-lpae-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-cloud-amd64-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-cloud-amd64-unsigned", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-loongson-3", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-loongson-3-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-marvell", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-marvell-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-octeon", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-octeon-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-powerpc64le", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-powerpc64le-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rpi", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rpi-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-686-pae-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-686-pae-unsigned", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-amd64-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-amd64-unsigned", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-arm64-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-arm64-unsigned", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-armmp", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-armmp-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-s390x", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-s390x-dbg", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-amd64-signed-template", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-arm64-signed-template", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-i386-signed-template", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-kbuild-4.19", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-libc-dev", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-perf-4.19", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-source-4.19", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-support-4.19.0-5", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"lockdep", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-core-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"rtc-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"serial-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"speakup-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"uinput-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"uinput-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"uinput-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usbip", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-4kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-5kc-malta-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-armmp-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-loongson-3-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-marvell-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-octeon-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-s390x-di", reference:"4.19.67-2+deb10u2")) flag++;
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.189-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.189-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
