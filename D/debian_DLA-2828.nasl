#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2828. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155711);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/29");

  script_cve_id("CVE-2017-14160", "CVE-2018-10392", "CVE-2018-10393");

  script_name(english:"Debian DLA-2828-1 : libvorbis - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2828 advisory.

  - The bark_noise_hybridmp function in psy.c in Xiph.Org libvorbis 1.3.5 allows remote attackers to cause a
    denial of service (out-of-bounds access and application crash) or possibly have unspecified other impact
    via a crafted mp4 file. (CVE-2017-14160)

  - mapping0_forward in mapping0.c in Xiph.Org libvorbis 1.3.6 does not validate the number of channels, which
    allows remote attackers to cause a denial of service (heap-based buffer overflow or over-read) or possibly
    have unspecified other impact via a crafted file. (CVE-2018-10392)

  - bark_noise_hybridmp in psy.c in Xiph.Org libvorbis 1.3.6 has a stack-based buffer over-read.
    (CVE-2018-10393)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=876780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libvorbis");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2828");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-14160");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10392");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10393");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libvorbis");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libvorbis packages.

For Debian 9 stretch, these problems have been fixed in version 1.3.5-4+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvorbis-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvorbis-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvorbis0a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvorbisenc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvorbisfile3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'libvorbis-dbg', 'reference': '1.3.5-4+deb9u3'},
    {'release': '9.0', 'prefix': 'libvorbis-dev', 'reference': '1.3.5-4+deb9u3'},
    {'release': '9.0', 'prefix': 'libvorbis0a', 'reference': '1.3.5-4+deb9u3'},
    {'release': '9.0', 'prefix': 'libvorbisenc2', 'reference': '1.3.5-4+deb9u3'},
    {'release': '9.0', 'prefix': 'libvorbisfile3', 'reference': '1.3.5-4+deb9u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvorbis-dbg / libvorbis-dev / libvorbis0a / libvorbisenc2 / etc');
}
