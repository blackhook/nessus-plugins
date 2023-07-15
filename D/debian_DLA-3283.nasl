#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3283. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170697);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/27");

  script_cve_id("CVE-2022-39956", "CVE-2022-48279", "CVE-2023-24021");

  script_name(english:"Debian DLA-3283-1 : modsecurity-apache - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3283 advisory.

  - The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule set bypass for HTTP multipart
    requests by submitting a payload that uses a character encoding scheme via the Content-Type or the
    deprecated Content-Transfer-Encoding multipart MIME header fields that will not be decoded and inspected
    by the web application firewall engine and the rule set. The multipart payload will therefore bypass
    detection. A vulnerable backend that supports these encoding schemes can potentially be exploited. The
    legacy CRS versions 3.0.x and 3.1.x are affected, as well as the currently supported versions 3.2.1 and
    3.3.2. Integrators and users are advised upgrade to 3.2.2 and 3.3.3 respectively. The mitigation against
    these vulnerabilities depends on the installation of the latest ModSecurity version (v2.9.6 / v3.0.8).
    (CVE-2022-39956)

  - In ModSecurity before 2.9.6 and 3.x before 3.0.8, HTTP multipart requests were incorrectly parsed and
    could bypass the Web Application Firewall. NOTE: this is related to CVE-2022-39956 but can be considered
    independent changes to the ModSecurity (C language) codebase. (CVE-2022-48279)

  - Incorrect handling of '\0' bytes in file uploads in ModSecurity before 2.9.7 may allow for Web Application
    Firewall bypasses and buffer overflows on the Web Application Firewall when executing rules that read the
    FILES_TMP_CONTENT collection. (CVE-2023-24021)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1029329");
  # https://security-tracker.debian.org/tracker/source-package/modsecurity-apache
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b86f5745");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39956");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48279");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24021");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/modsecurity-apache");
  script_set_attribute(attribute:"solution", value:
"Upgrade the modsecurity-apache packages.

For Debian 10 buster, these problems have been fixed in version 2.9.3-1+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-security2");
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
    {'release': '10.0', 'prefix': 'libapache2-mod-security2', 'reference': '2.9.3-1+deb10u2'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-security2');
}
