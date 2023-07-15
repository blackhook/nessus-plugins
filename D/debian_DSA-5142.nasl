#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5142. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161434);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/03");

  script_cve_id("CVE-2022-29824");

  script_name(english:"Debian DSA-5142-1 : libxml2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5142
advisory.

  - In libxml2 before 2.9.14, several buffer handling functions in buf.c (xmlBuf*) and tree.c (xmlBuffer*)
    don't check for integer overflows. This can result in out-of-bounds memory writes. Exploitation requires a
    victim to open a crafted, multi-gigabyte XML file. Other software using libxml2's buffer functions, for
    example libxslt through 1.1.35, is affected as well. (CVE-2022-29824)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1010526");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libxml2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5142");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29824");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libxml2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libxml2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libxml2 packages.

For the stable distribution (bullseye), this problem has been fixed in version 2.9.10+dfsg-6.7+deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29824");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libxml2', 'reference': '2.9.4+dfsg1-7+deb10u4'},
    {'release': '10.0', 'prefix': 'libxml2-dbg', 'reference': '2.9.4+dfsg1-7+deb10u4'},
    {'release': '10.0', 'prefix': 'libxml2-dev', 'reference': '2.9.4+dfsg1-7+deb10u4'},
    {'release': '10.0', 'prefix': 'libxml2-doc', 'reference': '2.9.4+dfsg1-7+deb10u4'},
    {'release': '10.0', 'prefix': 'libxml2-utils', 'reference': '2.9.4+dfsg1-7+deb10u4'},
    {'release': '10.0', 'prefix': 'python-libxml2', 'reference': '2.9.4+dfsg1-7+deb10u4'},
    {'release': '10.0', 'prefix': 'python-libxml2-dbg', 'reference': '2.9.4+dfsg1-7+deb10u4'},
    {'release': '10.0', 'prefix': 'python3-libxml2', 'reference': '2.9.4+dfsg1-7+deb10u4'},
    {'release': '10.0', 'prefix': 'python3-libxml2-dbg', 'reference': '2.9.4+dfsg1-7+deb10u4'},
    {'release': '11.0', 'prefix': 'libxml2', 'reference': '2.9.10+dfsg-6.7+deb11u2'},
    {'release': '11.0', 'prefix': 'libxml2-dbg', 'reference': '2.9.10+dfsg-6.7+deb11u2'},
    {'release': '11.0', 'prefix': 'libxml2-dev', 'reference': '2.9.10+dfsg-6.7+deb11u2'},
    {'release': '11.0', 'prefix': 'libxml2-doc', 'reference': '2.9.10+dfsg-6.7+deb11u2'},
    {'release': '11.0', 'prefix': 'libxml2-utils', 'reference': '2.9.10+dfsg-6.7+deb11u2'},
    {'release': '11.0', 'prefix': 'python-libxml2', 'reference': '2.9.10+dfsg-6.7+deb11u2'},
    {'release': '11.0', 'prefix': 'python-libxml2-dbg', 'reference': '2.9.10+dfsg-6.7+deb11u2'},
    {'release': '11.0', 'prefix': 'python3-libxml2', 'reference': '2.9.10+dfsg-6.7+deb11u2'},
    {'release': '11.0', 'prefix': 'python3-libxml2-dbg', 'reference': '2.9.10+dfsg-6.7+deb11u2'}
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
