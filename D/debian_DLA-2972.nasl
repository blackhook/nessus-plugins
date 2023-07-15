#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2972. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159615);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/09");

  script_cve_id(
    "CVE-2016-9318",
    "CVE-2017-5130",
    "CVE-2017-5969",
    "CVE-2017-16932",
    "CVE-2022-23308"
  );
  script_xref(name:"IAVB", value:"2017-B-0143-S");

  script_name(english:"Debian DLA-2972-1 : libxml2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2972 advisory.

  - libxml2 2.9.4 and earlier, as used in XMLSec 1.2.23 and earlier and other products, does not offer a flag
    directly indicating that the current document may be read but other files may not be opened, which makes
    it easier for remote attackers to conduct XML External Entity (XXE) attacks via a crafted document.
    (CVE-2016-9318)

  - parser.c in libxml2 before 2.9.5 does not prevent infinite recursion in parameter entities.
    (CVE-2017-16932)

  - An integer overflow in xmlmemory.c in libxml2 before 2.9.5, as used in Google Chrome prior to 62.0.3202.62
    and other products, allowed a remote attacker to potentially exploit heap corruption via a crafted XML
    file. (CVE-2017-5130)

  - ** DISPUTED ** libxml2 2.9.4, when used in recover mode, allows remote attackers to cause a denial of
    service (NULL pointer dereference) via a crafted XML document. NOTE: The maintainer states I would
    disagree of a CVE with the Recover parsing option which should only be used for manual recovery at least
    for XML parser. (CVE-2017-5969)

  - valid.c in libxml2 before 2.9.13 has a use-after-free of ID and IDREF attributes. (CVE-2022-23308)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libxml2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2972");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2016-9318");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-16932");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-5130");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-5969");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23308");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libxml2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libxml2 packages.

For Debian 9 stretch, these problems have been fixed in version 2.9.4+dfsg1-2.2+deb9u6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5130");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '9.0', 'prefix': 'libxml2', 'reference': '2.9.4+dfsg1-2.2+deb9u6'},
    {'release': '9.0', 'prefix': 'libxml2-dbg', 'reference': '2.9.4+dfsg1-2.2+deb9u6'},
    {'release': '9.0', 'prefix': 'libxml2-dev', 'reference': '2.9.4+dfsg1-2.2+deb9u6'},
    {'release': '9.0', 'prefix': 'libxml2-doc', 'reference': '2.9.4+dfsg1-2.2+deb9u6'},
    {'release': '9.0', 'prefix': 'libxml2-utils', 'reference': '2.9.4+dfsg1-2.2+deb9u6'},
    {'release': '9.0', 'prefix': 'libxml2-utils-dbg', 'reference': '2.9.4+dfsg1-2.2+deb9u6'},
    {'release': '9.0', 'prefix': 'python-libxml2', 'reference': '2.9.4+dfsg1-2.2+deb9u6'},
    {'release': '9.0', 'prefix': 'python-libxml2-dbg', 'reference': '2.9.4+dfsg1-2.2+deb9u6'},
    {'release': '9.0', 'prefix': 'python3-libxml2', 'reference': '2.9.4+dfsg1-2.2+deb9u6'},
    {'release': '9.0', 'prefix': 'python3-libxml2-dbg', 'reference': '2.9.4+dfsg1-2.2+deb9u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxml2 / libxml2-dbg / libxml2-dev / libxml2-doc / libxml2-utils / etc');
}
