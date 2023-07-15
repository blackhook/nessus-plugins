#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2772. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(153810);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/04");

  script_cve_id("CVE-2017-12678", "CVE-2018-11439");

  script_name(english:"Debian DLA-2772-1 : taglib - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2772 advisory.

  - In TagLib 1.11.1, the rebuildAggregateFrames function in id3v2framefactory.cpp has a pointer to cast
    vulnerability, which allows remote attackers to cause a denial of service or possibly have unspecified
    other impact via a crafted audio file. (CVE-2017-12678)

  - The TagLib::Ogg::FLAC::File::scan function in oggflacfile.cpp in TagLib 1.11.1 allows remote attackers to
    cause information disclosure (heap-based buffer over-read) via a crafted audio file. (CVE-2018-11439)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=871511");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/taglib");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12678");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-11439");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/taglib");
  script_set_attribute(attribute:"solution", value:
"Upgrade the taglib packages.

For Debian 9 stretch, these problems have been fixed in version 1.11.1+dfsg.1-0.3+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12678");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtag1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtag1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtag1v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtag1v5-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtagc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtagc0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libtag1-dev', 'reference': '1.11.1+dfsg.1-0.3+deb9u1'},
    {'release': '9.0', 'prefix': 'libtag1-doc', 'reference': '1.11.1+dfsg.1-0.3+deb9u1'},
    {'release': '9.0', 'prefix': 'libtag1v5', 'reference': '1.11.1+dfsg.1-0.3+deb9u1'},
    {'release': '9.0', 'prefix': 'libtag1v5-vanilla', 'reference': '1.11.1+dfsg.1-0.3+deb9u1'},
    {'release': '9.0', 'prefix': 'libtagc0', 'reference': '1.11.1+dfsg.1-0.3+deb9u1'},
    {'release': '9.0', 'prefix': 'libtagc0-dev', 'reference': '1.11.1+dfsg.1-0.3+deb9u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtag1-dev / libtag1-doc / libtag1v5 / libtag1v5-vanilla / libtagc0 / etc');
}
