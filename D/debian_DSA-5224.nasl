#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5224. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164813);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2022-27337", "CVE-2022-38784");
  script_xref(name:"IAVB", value:"2022-B-0033-S");
  script_xref(name:"IAVB", value:"2022-B-0039-S");
  script_xref(name:"IAVB", value:"2022-B-0050");

  script_name(english:"Debian DSA-5224-1 : poppler - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5224 advisory.

  - A logic error in the Hints::Hints function of Poppler v22.03.0 allows attackers to cause a Denial of
    Service (DoS) via a crafted PDF file. (CVE-2022-27337)

  - Poppler prior to and including 22.08.0 contains an integer overflow in the JBIG2 decoder
    (JBIG2Stream::readTextRegionSeg() in JBIGStream.cc). Processing a specially crafted PDF file or JBIG2
    image could lead to a crash or the execution of arbitrary code. This is similar to the vulnerability
    described by CVE-2022-38171 in Xpdf. (CVE-2022-38784)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1010695");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/poppler");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5224");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27337");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38784");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/poppler");
  script_set_attribute(attribute:"solution", value:
"Upgrade the poppler packages.

For the stable distribution (bullseye), these problems have been fixed in version 20.09.0-3.1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27337");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-38784");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-poppler-0.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp0v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler102");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gir1.2-poppler-0.18', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler-cpp-dev', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler-cpp0v5', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler-dev', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler-glib-dev', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler-glib-doc', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler-glib8', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler-private-dev', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler-qt5-1', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler-qt5-dev', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpoppler102', 'reference': '20.09.0-3.1+deb11u1'},
    {'release': '11.0', 'prefix': 'poppler-utils', 'reference': '20.09.0-3.1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-poppler-0.18 / libpoppler-cpp-dev / libpoppler-cpp0v5 / etc');
}
