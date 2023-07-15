#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4867. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146986);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/12");

  script_cve_id("CVE-2020-14372", "CVE-2020-25632", "CVE-2020-25647", "CVE-2020-27749", "CVE-2020-27779", "CVE-2021-20225", "CVE-2021-20233");
  script_xref(name:"DSA", value:"4867");

  script_name(english:"Debian DSA-4867-1 : grub2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the GRUB2 bootloader.

  - CVE-2020-14372
    It was discovered that the acpi command allows a
    privileged user to load crafted ACPI tables when Secure
    Boot is enabled.

  - CVE-2020-25632
    A use-after-free vulnerability was found in the rmmod
    command.

  - CVE-2020-25647
    An out-of-bound write vulnerability was found in the
    grub_usb_device_initialize() function, which is called
    to handle USB device initialization.

  - CVE-2020-27749
    A stack-based buffer overflow flaw was found in
    grub_parser_split_cmdline.

  - CVE-2020-27779
    It was discovered that the cutmem command allows a
    privileged user to remove memory regions when Secure
    Boot is enabled.

  - CVE-2021-20225
    A heap out-of-bounds write vulnerability was found in
    the short form option parser.

  - CVE-2021-20233
    A heap out-of-bound write flaw was found caused by
    mis-calculation of space required for quoting in the
    menu rendering.

Further detailed information can be found at
https://www.debian.org/security/2021-GRUB-UEFI-SecureBoot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-14372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-25632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-25647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-27749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-27779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-20225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-20233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021-GRUB-UEFI-SecureBoot"
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
    value:"https://www.debian.org/security/2021/dsa-4867"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the grub2 packages.

For the stable distribution (buster), these problems have been fixed
in version 2.02+dfsg1-20+deb10u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20233");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"grub-common", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-coreboot", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-coreboot-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-coreboot-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-amd64", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-amd64-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-amd64-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-amd64-signed-template", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm64", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm64-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm64-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-arm64-signed-template", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-ia32", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-ia32-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-ia32-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-efi-ia32-signed-template", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-emu", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-emu-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-firmware-qemu", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-ieee1275", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-ieee1275-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-ieee1275-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-linuxbios", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-mount-udeb", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-pc", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-pc-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-pc-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-rescue-pc", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-theme-starfield", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-uboot", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-uboot-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-uboot-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-xen", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-xen-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-xen-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-xen-host", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-yeeloong", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-yeeloong-bin", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub-yeeloong-dbg", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub2", reference:"2.02+dfsg1-20+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"grub2-common", reference:"2.02+dfsg1-20+deb10u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
