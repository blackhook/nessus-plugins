#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3144. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166020);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id(
    "CVE-2022-23096",
    "CVE-2022-23097",
    "CVE-2022-23098",
    "CVE-2022-32293"
  );

  script_name(english:"Debian DLA-3144-1 : connman - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3144 advisory.

  - An issue was discovered in the DNS proxy in Connman through 1.40. The TCP server reply implementation
    lacks a check for the presence of sufficient Header Data, leading to an out-of-bounds read.
    (CVE-2022-23096)

  - An issue was discovered in the DNS proxy in Connman through 1.40. forward_dns_reply mishandles a strnlen
    call, leading to an out-of-bounds read. (CVE-2022-23097)

  - An issue was discovered in the DNS proxy in Connman through 1.40. The TCP server reply implementation has
    an infinite loop if no data is received. (CVE-2022-23098)

  - In ConnMan through 1.41, a man-in-the-middle attack against a WISPR HTTP query could be used to trigger a
    use-after-free in WISPR handling, leading to crashes or code execution. (CVE-2022-32293)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1004935");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/connman");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3144");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23096");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23097");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23098");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32293");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/connman");
  script_set_attribute(attribute:"solution", value:
"Upgrade the connman packages.

For Debian 10 buster, these problems have been fixed in version 1.36-2.1~deb10u4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:connman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:connman-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:connman-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:connman-vpn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'connman', 'reference': '1.36-2.1~deb10u4'},
    {'release': '10.0', 'prefix': 'connman-dev', 'reference': '1.36-2.1~deb10u4'},
    {'release': '10.0', 'prefix': 'connman-doc', 'reference': '1.36-2.1~deb10u4'},
    {'release': '10.0', 'prefix': 'connman-vpn', 'reference': '1.36-2.1~deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'connman / connman-dev / connman-doc / connman-vpn');
}
