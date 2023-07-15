#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3096. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164676);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id("CVE-2020-27792");
  script_xref(name:"IAVB", value:"2022-B-0034-S");

  script_name(english:"Debian DLA-3096-1 : ghostscript - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3096
advisory.

  - A heap-based buffer over write vulnerability was found in GhostScript's lp8000_print_page() function in
    gdevlp8k.c file. An attacker could trick a user to open a crafted PDF file, triggering the heap buffer
    overflow that could lead to memory corruption or a denial of service. (CVE-2020-27792)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ghostscript");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3096");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27792");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ghostscript");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ghostscript packages.

For Debian 10 buster, this problem has been fixed in version 9.27~dfsg-2+deb10u6.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27792");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'ghostscript', 'reference': '9.27~dfsg-2+deb10u6'},
    {'release': '10.0', 'prefix': 'ghostscript-dbg', 'reference': '9.27~dfsg-2+deb10u6'},
    {'release': '10.0', 'prefix': 'ghostscript-doc', 'reference': '9.27~dfsg-2+deb10u6'},
    {'release': '10.0', 'prefix': 'ghostscript-x', 'reference': '9.27~dfsg-2+deb10u6'},
    {'release': '10.0', 'prefix': 'libgs-dev', 'reference': '9.27~dfsg-2+deb10u6'},
    {'release': '10.0', 'prefix': 'libgs9', 'reference': '9.27~dfsg-2+deb10u6'},
    {'release': '10.0', 'prefix': 'libgs9-common', 'reference': '9.27~dfsg-2+deb10u6'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
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
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ghostscript / ghostscript-dbg / ghostscript-doc / ghostscript-x / etc');
}
