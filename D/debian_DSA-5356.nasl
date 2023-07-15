#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5356. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171811);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/22");

  script_cve_id(
    "CVE-2021-3643",
    "CVE-2021-23159",
    "CVE-2021-23172",
    "CVE-2021-23210",
    "CVE-2021-33844",
    "CVE-2021-40426",
    "CVE-2022-31650",
    "CVE-2022-31651"
  );

  script_name(english:"Debian DSA-5356-1 : sox - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5356 advisory.

  - A vulnerability was found in SoX, where a heap-buffer-overflow occurs in function lsx_read_w_buf() in
    formats_i.c file. The vulnerability is exploitable with a crafted file, that could cause an application to
    crash. (CVE-2021-23159)

  - A vulnerability was found in SoX, where a heap-buffer-overflow occurs in function startread() in hcom.c
    file. The vulnerability is exploitable with a crafted hcomn file, that could cause an application to
    crash. (CVE-2021-23172)

  - A floating point exception (divide-by-zero) issue was discovered in SoX in functon read_samples() of voc.c
    file. An attacker with a crafted file, could cause an application to crash. (CVE-2021-23210)

  - A floating point exception (divide-by-zero) issue was discovered in SoX in functon startread() of wav.c
    file. An attacker with a crafted wav file, could cause an application to crash. (CVE-2021-33844)

  - A flaw was found in sox 14.4.1. The lsx_adpcm_init function within libsox leads to a global-buffer-
    overflow. This flaw allows an attacker to input a malicious file, leading to the disclosure of sensitive
    information. (CVE-2021-3643)

  - A heap-based buffer overflow vulnerability exists in the sphere.c start_read() functionality of Sound
    Exchange libsox 14.4.2 and master commit 42b3557e. A specially-crafted file can lead to a heap buffer
    overflow. An attacker can provide a malicious file to trigger this vulnerability. (CVE-2021-40426)

  - In SoX 14.4.2, there is a floating-point exception in lsx_aiffstartwrite in aiff.c in libsox.a.
    (CVE-2022-31650)

  - In SoX 14.4.2, there is an assertion failure in rate_init in rate.c in libsox.a. (CVE-2022-31651)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1010374");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sox");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5356");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23159");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23172");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23210");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33844");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3643");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40426");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31650");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31651");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/sox");
  script_set_attribute(attribute:"solution", value:
"Upgrade the sox packages.

For the stable distribution (bullseye), these problems have been fixed in version 14.4.2+git20190427-2+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40426");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-ao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-pulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libsox-dev', 'reference': '14.4.2+git20190427-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsox-fmt-all', 'reference': '14.4.2+git20190427-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsox-fmt-alsa', 'reference': '14.4.2+git20190427-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsox-fmt-ao', 'reference': '14.4.2+git20190427-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsox-fmt-base', 'reference': '14.4.2+git20190427-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsox-fmt-mp3', 'reference': '14.4.2+git20190427-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsox-fmt-oss', 'reference': '14.4.2+git20190427-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsox-fmt-pulse', 'reference': '14.4.2+git20190427-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsox3', 'reference': '14.4.2+git20190427-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sox', 'reference': '14.4.2+git20190427-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsox-dev / libsox-fmt-all / libsox-fmt-alsa / libsox-fmt-ao / etc');
}
