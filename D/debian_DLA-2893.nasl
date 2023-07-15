#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2893. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156963);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/23");

  script_cve_id("CVE-2022-22815", "CVE-2022-22816", "CVE-2022-22817");

  script_name(english:"Debian DLA-2893-1 : pillow - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2893 advisory.

  - path_getbbox in path.c in Pillow before 9.0.0 improperly initializes ImagePath.Path. (CVE-2022-22815)

  - path_getbbox in path.c in Pillow before 9.0.0 has a buffer over-read during initialization of
    ImagePath.Path. (CVE-2022-22816)

  - PIL.ImageMath.eval in Pillow before 9.0.0 allows evaluation of arbitrary expressions, such as ones that
    use the Python exec method. (CVE-2022-22817)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/pillow");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2893");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22815");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22816");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22817");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/pillow");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pillow packages.

For Debian 9 stretch, these problems have been fixed in version 4.0.0-4+deb9u4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22817");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-imaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil.imagetk-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil.imagetk-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
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
    {'release': '9.0', 'prefix': 'python-imaging', 'reference': '4.0.0-4+deb9u4'},
    {'release': '9.0', 'prefix': 'python-pil', 'reference': '4.0.0-4+deb9u4'},
    {'release': '9.0', 'prefix': 'python-pil-dbg', 'reference': '4.0.0-4+deb9u4'},
    {'release': '9.0', 'prefix': 'python-pil-doc', 'reference': '4.0.0-4+deb9u4'},
    {'release': '9.0', 'prefix': 'python-pil.imagetk', 'reference': '4.0.0-4+deb9u4'},
    {'release': '9.0', 'prefix': 'python-pil.imagetk-dbg', 'reference': '4.0.0-4+deb9u4'},
    {'release': '9.0', 'prefix': 'python3-pil', 'reference': '4.0.0-4+deb9u4'},
    {'release': '9.0', 'prefix': 'python3-pil-dbg', 'reference': '4.0.0-4+deb9u4'},
    {'release': '9.0', 'prefix': 'python3-pil.imagetk', 'reference': '4.0.0-4+deb9u4'},
    {'release': '9.0', 'prefix': 'python3-pil.imagetk-dbg', 'reference': '4.0.0-4+deb9u4'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-imaging / python-pil / python-pil-dbg / python-pil-doc / etc');
}
