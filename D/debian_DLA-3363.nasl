#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3363. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172599);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2019-20454", "CVE-2022-1586", "CVE-2022-1587");

  script_name(english:"Debian DLA-3363-1 : pcre2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3363 advisory.

  - An out-of-bounds read was discovered in PCRE before 10.34 when the pattern \X is JIT compiled and used to
    match specially crafted subjects in non-UTF mode. Applications that use PCRE to parse untrusted input may
    be vulnerable to this flaw, which would allow an attacker to crash the application. The flaw occurs in
    do_extuni_no_utf in pcre2_jit_compile.c. (CVE-2019-20454)

  - An out-of-bounds read vulnerability was discovered in the PCRE2 library in the
    compile_xclass_matchingpath() function of the pcre2_jit_compile.c file. This involves a unicode property
    matching issue in JIT-compiled regular expressions. The issue occurs because the character was not fully
    read in case-less matching within JIT. (CVE-2022-1586)

  - An out-of-bounds read vulnerability was discovered in the PCRE2 library in the get_recurse_data_length()
    function of the pcre2_jit_compile.c file. This issue affects recursions in JIT-compiled regular
    expressions caused by duplicate data transfers. (CVE-2022-1587)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1011954");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/pcre2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3363");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-20454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1587");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/pcre2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pcre2 packages.

For Debian 10 buster, these problems have been fixed in version 10.32-5+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre2-16-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre2-32-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre2-8-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre2-posix0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pcre2-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libpcre2-16-0', 'reference': '10.32-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpcre2-32-0', 'reference': '10.32-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpcre2-8-0', 'reference': '10.32-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpcre2-dbg', 'reference': '10.32-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpcre2-dev', 'reference': '10.32-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpcre2-posix0', 'reference': '10.32-5+deb10u1'},
    {'release': '10.0', 'prefix': 'pcre2-utils', 'reference': '10.32-5+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpcre2-16-0 / libpcre2-32-0 / libpcre2-8-0 / libpcre2-dbg / etc');
}
