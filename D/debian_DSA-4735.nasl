#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4735. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139099);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-10713", "CVE-2020-14308", "CVE-2020-14309", "CVE-2020-14310", "CVE-2020-14311", "CVE-2020-15706", "CVE-2020-15707");
  script_xref(name:"DSA", value:"4735");
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"Debian DSA-4735-1 : grub2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the GRUB2 bootloader.

  - CVE-2020-10713
    A flaw in the grub.cfg parsing code was found allowing
    to break UEFI Secure Boot and load arbitrary code.
    Details can be found at
    https://www.eclypsium.com/2020/07/29/theres-a-hole-in-th
    e-boot/

  - CVE-2020-14308
    It was discovered that grub_malloc does not validate the
    allocation size allowing for arithmetic overflow and
    subsequently a heap-based buffer overflow.

  - CVE-2020-14309
    An integer overflow in grub_squash_read_symlink may lead
    to a heap based buffer overflow.

  - CVE-2020-14310
    An integer overflow in read_section_from_string may lead
    to a heap based buffer overflow.

  - CVE-2020-14311
    An integer overflow in grub_ext2_read_link may lead to a
    heap-based buffer overflow.

  - CVE-2020-15706
    script: Avoid a use-after-free when redefining a
    function during execution.

  - CVE-2020-15707
    An integer overflow flaw was found in the initrd size
    handling.

Further detailed information can be found at
https://www.debian.org/security/2020-GRUB-UEFI-SecureBoot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-10713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.eclypsium.com/2020/07/29/theres-a-hole-in-the-boot/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-14308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-14309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-14310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-14311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-15706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-15707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020-GRUB-UEFI-SecureBoot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/grub2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/grub2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4735"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the grub2 packages.

For the stable distribution (buster), these problems have been fixed
in version 2.02+dfsg1-20+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14309");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"grub-common", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-coreboot", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-coreboot-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-coreboot-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-amd64", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-amd64-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-amd64-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-amd64-signed-template", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm64", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm64-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm64-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm64-signed-template", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-ia32", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-ia32-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-ia32-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-ia32-signed-template", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-emu", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-emu-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-firmware-qemu", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-ieee1275", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-ieee1275-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-ieee1275-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-linuxbios", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-mount-udeb", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-pc", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-pc-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-pc-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-rescue-pc", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-theme-starfield", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-uboot", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-uboot-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-uboot-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-xen", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-xen-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-xen-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-xen-host", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-yeeloong", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-yeeloong-bin", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub-yeeloong-dbg", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub2", reference:"2.02+dfsg1-20+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"grub2-common", reference:"2.02+dfsg1-20+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
