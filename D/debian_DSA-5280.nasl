#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5280. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(167746);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/19");

  script_cve_id("CVE-2022-2601", "CVE-2022-3775");

  script_name(english:"Debian DSA-5280-1 : grub2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5280 advisory.

  - grub2: Buffer overflow in grub_font_construct_glyph() can lead to out-of-bound write and possible secure
    boot bypass (CVE-2022-2601)

  - grub2: Heap based out-of-bounds write when redering certain unicode sequences (CVE-2022-3775)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/grub2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5280");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3775");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/grub2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the grub2 packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.06-3~deb11u4.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-coreboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-coreboot-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-coreboot-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-amd64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-arm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-arm-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-arm64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-ia32-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-ia32-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-ia32-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-emu-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-firmware-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-ieee1275");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-ieee1275-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-ieee1275-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-linuxbios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-mount-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-pc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-pc-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-rescue-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-theme-starfield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-uboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-uboot-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-uboot-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-xen-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-xen-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-xen-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-yeeloong");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-yeeloong-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-yeeloong-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'grub-common', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-coreboot', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-coreboot-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-coreboot-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-amd64', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-amd64-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-amd64-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-amd64-signed-template', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-arm', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-arm-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-arm-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-arm64', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-arm64-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-arm64-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-arm64-signed-template', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-ia32', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-ia32-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-ia32-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-efi-ia32-signed-template', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-emu', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-emu-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-firmware-qemu', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-ieee1275', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-ieee1275-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-ieee1275-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-linuxbios', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-mount-udeb', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-pc', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-pc-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-pc-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-rescue-pc', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-theme-starfield', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-uboot', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-uboot-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-uboot-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-xen', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-xen-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-xen-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-xen-host', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-yeeloong', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-yeeloong-bin', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub-yeeloong-dbg', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub2', 'reference': '2.06-3~deb11u4'},
    {'release': '11.0', 'prefix': 'grub2-common', 'reference': '2.06-3~deb11u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub-common / grub-coreboot / grub-coreboot-bin / grub-coreboot-dbg / etc');
}
