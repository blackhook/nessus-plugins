#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3060. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162597);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2022-0544", "CVE-2022-0545", "CVE-2022-0546");

  script_name(english:"Debian DLA-3060-1 : blender - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3060 advisory.

  - An integer underflow in the DDS loader of Blender leads to an out-of-bounds read, possibly allowing an
    attacker to read sensitive data using a crafted DDS image file. This flaw affects Blender versions prior
    to 2.83.19, 2.93.8 and 3.1. (CVE-2022-0544)

  - An integer overflow in the processing of loaded 2D images leads to a write-what-where vulnerability and an
    out-of-bounds read vulnerability, allowing an attacker to leak sensitive information or achieve code
    execution in the context of the Blender process when a specially crafted image file is loaded. This flaw
    affects Blender versions prior to 2.83.19, 2.93.8 and 3.1. (CVE-2022-0545)

  - A missing bounds check in the image loader used in Blender 3.x and 2.93.8 leads to out-of-bounds heap
    access, allowing an attacker to cause denial of service, memory corruption or potentially code execution.
    (CVE-2022-0546)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/blender");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3060");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0544");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0546");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/blender");
  script_set_attribute(attribute:"solution", value:
"Upgrade the blender packages.

For Debian 9 stretch, these problems have been fixed in version 2.79.b+dfsg0-1~deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0546");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:blender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:blender-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:blender-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'blender', 'reference': '2.79.b+dfsg0-1~deb9u2'},
    {'release': '9.0', 'prefix': 'blender-data', 'reference': '2.79.b+dfsg0-1~deb9u2'},
    {'release': '9.0', 'prefix': 'blender-dbg', 'reference': '2.79.b+dfsg0-1~deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'blender / blender-data / blender-dbg');
}
