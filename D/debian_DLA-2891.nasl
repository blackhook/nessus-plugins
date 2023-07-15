#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2891. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156954);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/22");

  script_cve_id(
    "CVE-2021-33196",
    "CVE-2021-36221",
    "CVE-2021-39293",
    "CVE-2021-41771",
    "CVE-2021-44716",
    "CVE-2021-44717"
  );

  script_name(english:"Debian DLA-2891-1 : golang-1.8 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2891 advisory.

  - In archive/zip in Go before 1.15.13 and 1.16.x before 1.16.5, a crafted file count (in an archive's
    header) can cause a NewReader or OpenReader panic. (CVE-2021-33196)

  - Go before 1.15.15 and 1.16.x before 1.16.7 has a race condition that can lead to a net/http/httputil
    ReverseProxy panic upon an ErrAbortHandler abort. (CVE-2021-36221)

  - ImportedSymbols in debug/macho (for Open or OpenFat) in Go before 1.16.10 and 1.17.x before 1.17.3
    Accesses a Memory Location After the End of a Buffer, aka an out-of-bounds slice situation.
    (CVE-2021-41771)

  - net/http in Go before 1.16.12 and 1.17.x before 1.17.5 allows uncontrolled memory consumption in the
    header canonicalization cache via HTTP/2 requests. (CVE-2021-44716)

  - Go before 1.16.12 and 1.17.x before 1.17.5 on UNIX allows write operations to an unintended file or
    unintended network connection as a consequence of erroneous closing of file descriptor 0 after file-
    descriptor exhaustion. (CVE-2021-44717)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=989492");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/golang-1.8");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2891");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36221");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39293");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44716");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44717");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/golang-1.8");
  script_set_attribute(attribute:"solution", value:
"Upgrade the golang-1.8 packages.

For Debian 9 stretch, these problems have been fixed in version 1.8.1-1+deb9u4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44717");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.8-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.8-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.8-src");
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
    {'release': '9.0', 'prefix': 'golang-1.8', 'reference': '1.8.1-1+deb9u4'},
    {'release': '9.0', 'prefix': 'golang-1.8-doc', 'reference': '1.8.1-1+deb9u4'},
    {'release': '9.0', 'prefix': 'golang-1.8-go', 'reference': '1.8.1-1+deb9u4'},
    {'release': '9.0', 'prefix': 'golang-1.8-src', 'reference': '1.8.1-1+deb9u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-1.8 / golang-1.8-doc / golang-1.8-go / golang-1.8-src');
}
