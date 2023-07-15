#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2734. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152547);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2021-22898", "CVE-2021-22924");

  script_name(english:"Debian DLA-2734-1 : curl - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2734 advisory.

  - curl 7.7 through 7.76.1 suffers from an information disclosure when the `-t` command line option, known as
    `CURLOPT_TELNETOPTIONS` in libcurl, is used to send variable=content pairs to TELNET servers. Due to a
    flaw in the option parser for sending NEW_ENV variables, libcurl could be made to pass on uninitialized
    data from a stack based buffer to the server, resulting in potentially revealing sensitive internal
    information to the server using a clear-text network protocol. (CVE-2021-22898)

  - libcurl keeps previously used connections in a connection pool for subsequenttransfers to reuse, if one of
    them matches the setup.Due to errors in the logic, the config matching function did not take 'issuercert'
    into account and it compared the involved paths *case insensitively*,which could lead to libcurl reusing
    wrong connections.File paths are, or can be, case sensitive on many systems but not all, and caneven vary
    depending on used file systems.The comparison also didn't include the 'issuer cert' which a transfer can
    setto qualify how to verify the server certificate. (CVE-2021-22924)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/curl");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2734");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22924");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/curl");
  script_set_attribute(attribute:"solution", value:
"Upgrade the curl packages.

For Debian 9 stretch, these problems have been fixed in version 7.52.1-5+deb9u15.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22924");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'curl', 'reference': '7.52.1-5+deb9u15'},
    {'release': '9.0', 'prefix': 'libcurl3', 'reference': '7.52.1-5+deb9u15'},
    {'release': '9.0', 'prefix': 'libcurl3-dbg', 'reference': '7.52.1-5+deb9u15'},
    {'release': '9.0', 'prefix': 'libcurl3-gnutls', 'reference': '7.52.1-5+deb9u15'},
    {'release': '9.0', 'prefix': 'libcurl3-nss', 'reference': '7.52.1-5+deb9u15'},
    {'release': '9.0', 'prefix': 'libcurl4-doc', 'reference': '7.52.1-5+deb9u15'},
    {'release': '9.0', 'prefix': 'libcurl4-gnutls-dev', 'reference': '7.52.1-5+deb9u15'},
    {'release': '9.0', 'prefix': 'libcurl4-nss-dev', 'reference': '7.52.1-5+deb9u15'},
    {'release': '9.0', 'prefix': 'libcurl4-openssl-dev', 'reference': '7.52.1-5+deb9u15'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3 / libcurl3-dbg / libcurl3-gnutls / libcurl3-nss / etc');
}
