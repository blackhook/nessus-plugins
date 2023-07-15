#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3110. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165206);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id("CVE-2021-3800");

  script_name(english:"Debian DLA-3110-1 : glib2.0 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3110
advisory.

  - A flaw was found in glib before version 2.63.6. Due to random charset alias, pkexec can leak content from
    files owned by privileged users to unprivileged ones under the right condition. (CVE-2021-3800)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/glib2.0");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3110");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3800");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/glib2.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade the glib2.0 packages.

For Debian 10 buster, this problem has been fixed in version 2.58.3-2+deb10u4.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglib2.0-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
    {'release': '10.0', 'prefix': 'libglib2.0-0', 'reference': '2.58.3-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libglib2.0-bin', 'reference': '2.58.3-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libglib2.0-data', 'reference': '2.58.3-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libglib2.0-dev', 'reference': '2.58.3-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libglib2.0-dev-bin', 'reference': '2.58.3-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libglib2.0-doc', 'reference': '2.58.3-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libglib2.0-tests', 'reference': '2.58.3-2+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libglib2.0-0 / libglib2.0-bin / libglib2.0-data / libglib2.0-dev / etc');
}
