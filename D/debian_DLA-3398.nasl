#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3398. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174685);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/01");

  script_cve_id(
    "CVE-2023-27533",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27538"
  );
  script_xref(name:"IAVA", value:"2023-A-0153-S");

  script_name(english:"Debian DLA-3398-1 : curl - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3398 advisory.

  - A vulnerability in input validation exists in curl <8.0 during communication using the TELNET protocol may
    allow an attacker to pass on maliciously crafted user name and telnet options during server negotiation.
    The lack of proper input scrubbing allows an attacker to send content or perform option negotiation
    without the application's intent. This vulnerability could be exploited if an application allows user
    input, thereby enabling attackers to execute arbitrary code on the system. (CVE-2023-27533)

  - An authentication bypass vulnerability exists in libcurl <8.0.0 in the FTP connection reuse feature that
    can result in wrong credentials being used during subsequent transfers. Previously created connections are
    kept in a connection pool for reuse if they match the current setup. However, certain FTP settings such as
    CURLOPT_FTP_ACCOUNT, CURLOPT_FTP_ALTERNATIVE_TO_USER, CURLOPT_FTP_SSL_CCC, and CURLOPT_USE_SSL were not
    included in the configuration match checks, causing them to match too easily. This could lead to libcurl
    using the wrong credentials when performing a transfer, potentially allowing unauthorized access to
    sensitive information. (CVE-2023-27535)

  - An authentication bypass vulnerability exists libcurl <8.0.0 in the connection reuse feature which can
    reuse previously established connections with incorrect user permissions due to a failure to check for
    changes in the CURLOPT_GSSAPI_DELEGATION option. This vulnerability affects krb5/kerberos/negotiate/GSSAPI
    transfers and could potentially result in unauthorized access to sensitive information. The safest option
    is to not reuse connections if the CURLOPT_GSSAPI_DELEGATION option has been changed. (CVE-2023-27536)

  - An authentication bypass vulnerability exists in libcurl prior to v8.0.0 where it reuses a previously
    established SSH connection despite the fact that an SSH option was modified, which should have prevented
    reuse. libcurl maintains a pool of previously used connections to reuse them for subsequent transfers if
    the configurations match. However, two SSH settings were omitted from the configuration check, allowing
    them to match easily, potentially leading to the reuse of an inappropriate connection. (CVE-2023-27538)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/curl");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3398");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27533");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27535");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27536");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27538");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/curl");
  script_set_attribute(attribute:"solution", value:
"Upgrade the curl packages.

For Debian 10 buster, these problems have been fixed in version 7.64.0-4+deb10u6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27533");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '10.0', 'prefix': 'curl', 'reference': '7.64.0-4+deb10u6'},
    {'release': '10.0', 'prefix': 'libcurl3-gnutls', 'reference': '7.64.0-4+deb10u6'},
    {'release': '10.0', 'prefix': 'libcurl3-nss', 'reference': '7.64.0-4+deb10u6'},
    {'release': '10.0', 'prefix': 'libcurl4', 'reference': '7.64.0-4+deb10u6'},
    {'release': '10.0', 'prefix': 'libcurl4-doc', 'reference': '7.64.0-4+deb10u6'},
    {'release': '10.0', 'prefix': 'libcurl4-gnutls-dev', 'reference': '7.64.0-4+deb10u6'},
    {'release': '10.0', 'prefix': 'libcurl4-nss-dev', 'reference': '7.64.0-4+deb10u6'},
    {'release': '10.0', 'prefix': 'libcurl4-openssl-dev', 'reference': '7.64.0-4+deb10u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3-gnutls / libcurl3-nss / libcurl4 / libcurl4-doc / etc');
}
