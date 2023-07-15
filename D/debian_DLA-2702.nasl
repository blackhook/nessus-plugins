#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2702. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151369);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/21");

  script_cve_id("CVE-2021-3630");

  script_name(english:"Debian DLA-2702-1 : djvulibre - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2702
advisory.

  - An out-of-bounds write vulnerability was found in DjVuLibre in DJVU::DjVuTXT::decode() in DjVuText.cpp via
    a crafted djvu file which may lead to crash and segmentation fault. This flaw affects DjVuLibre versions
    prior to 3.5.28. (CVE-2021-3630)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/djvulibre");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2702");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3630");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/djvulibre");
  script_set_attribute(attribute:"solution", value:
"Upgrade the djvulibre packages.

For Debian 9 stretch, this problem has been fixed in version 3.5.27.1-7+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3630");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djview3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djvulibre-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djvulibre-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djvulibre-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djvuserve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdjvulibre-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdjvulibre-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdjvulibre21");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'djview', 'reference': '3.5.27.1-7+deb9u2'},
    {'release': '9.0', 'prefix': 'djview3', 'reference': '3.5.27.1-7+deb9u2'},
    {'release': '9.0', 'prefix': 'djvulibre-bin', 'reference': '3.5.27.1-7+deb9u2'},
    {'release': '9.0', 'prefix': 'djvulibre-dbg', 'reference': '3.5.27.1-7+deb9u2'},
    {'release': '9.0', 'prefix': 'djvulibre-desktop', 'reference': '3.5.27.1-7+deb9u2'},
    {'release': '9.0', 'prefix': 'djvuserve', 'reference': '3.5.27.1-7+deb9u2'},
    {'release': '9.0', 'prefix': 'libdjvulibre-dev', 'reference': '3.5.27.1-7+deb9u2'},
    {'release': '9.0', 'prefix': 'libdjvulibre-text', 'reference': '3.5.27.1-7+deb9u2'},
    {'release': '9.0', 'prefix': 'libdjvulibre21', 'reference': '3.5.27.1-7+deb9u2'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'djview / djview3 / djvulibre-bin / djvulibre-dbg / djvulibre-desktop / etc');
}
