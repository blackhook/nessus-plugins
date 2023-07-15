#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2695. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151361);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/03");

  script_cve_id(
    "CVE-2021-31870",
    "CVE-2021-31871",
    "CVE-2021-31872",
    "CVE-2021-31873"
  );

  script_name(english:"Debian DLA-2695-1 : klibc - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2695 advisory.

  - An issue was discovered in klibc before 2.0.9. Multiplication in the calloc() function may result in an
    integer overflow and a subsequent heap buffer overflow. (CVE-2021-31870)

  - An issue was discovered in klibc before 2.0.9. An integer overflow in the cpio command may result in a
    NULL pointer dereference on 64-bit systems. (CVE-2021-31871)

  - An issue was discovered in klibc before 2.0.9. Multiple possible integer overflows in the cpio command on
    32-bit systems may result in a buffer overflow or other security impact. (CVE-2021-31872)

  - An issue was discovered in klibc before 2.0.9. Additions in the malloc() function may result in an integer
    overflow and a subsequent heap buffer overflow. (CVE-2021-31873)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=989505");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/klibc");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2695");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31870");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31871");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31872");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31873");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/klibc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the klibc packages.

For Debian 9 stretch, these problems have been fixed in version 2.0.4-9+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:klibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libklibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libklibc-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '9.0', 'prefix': 'klibc-utils', 'reference': '2.0.4-9+deb9u1'},
    {'release': '9.0', 'prefix': 'libklibc', 'reference': '2.0.4-9+deb9u1'},
    {'release': '9.0', 'prefix': 'libklibc-dev', 'reference': '2.0.4-9+deb9u1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'klibc-utils / libklibc / libklibc-dev');
}
