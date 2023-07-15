#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5360-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159385);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2020-9484",
    "CVE-2020-9494",
    "CVE-2020-13943",
    "CVE-2020-17527",
    "CVE-2021-25122",
    "CVE-2021-25329",
    "CVE-2021-30640",
    "CVE-2021-33037",
    "CVE-2021-41079"
  );
  script_xref(name:"USN", value:"5360-1");
  script_xref(name:"IAVA", value:"2020-A-0470");
  script_xref(name:"IAVA", value:"2020-A-0225-S");
  script_xref(name:"IAVA", value:"2020-A-0324");
  script_xref(name:"IAVA", value:"2020-A-0465-S");
  script_xref(name:"IAVA", value:"2020-A-0570-S");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0194-S");
  script_xref(name:"IAVA", value:"2021-A-0114-S");
  script_xref(name:"IAVA", value:"2021-A-0347");
  script_xref(name:"IAVA", value:"2021-A-0483");
  script_xref(name:"IAVA", value:"2021-A-0303-S");
  script_xref(name:"IAVA", value:"2021-A-0486-S");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Tomcat vulnerabilities (USN-5360-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5360-1 advisory.

  - When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to
    7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the
    server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is
    configured with sessionAttributeValueClassNameFilter=null (the default unless a SecurityManager is used)
    or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker
    knows the relative file path from the storage location used by FileStore to the file the attacker has
    control over; then, using a specifically crafted request, the attacker will be able to trigger remote code
    execution via deserialization of the file under their control. Note that all of conditions a) to d) must
    be true for the attack to succeed. (CVE-2020-9484)

  - Apache Traffic Server 6.0.0 to 6.2.3, 7.0.0 to 7.1.10, and 8.0.0 to 8.0.7 is vulnerable to certain types
    of HTTP/2 HEADERS frames that can cause the server to allocate a large amount of memory and spin the
    thread. (CVE-2020-9494)

  - If an HTTP/2 client connecting to Apache Tomcat 10.0.0-M1 to 10.0.0-M7, 9.0.0.M1 to 9.0.37 or 8.5.0 to
    8.5.57 exceeded the agreed maximum number of concurrent streams for a connection (in violation of the
    HTTP/2 protocol), it was possible that a subsequent request made on that connection could contain HTTP
    headers - including HTTP/2 pseudo headers - from a previous request rather than the intended headers. This
    could lead to users seeing responses for unexpected resources. (CVE-2020-13943)

  - While investigating bug 64830 it was discovered that Apache Tomcat 10.0.0-M1 to 10.0.0-M9, 9.0.0-M1 to
    9.0.39 and 8.5.0 to 8.5.59 could re-use an HTTP request header value from the previous stream received on
    an HTTP/2 connection for the request associated with the subsequent stream. While this would most likely
    lead to an error and the closure of the HTTP/2 connection, it is possible that information could leak
    between requests. (CVE-2020-17527)

  - When responding to new h2c connection requests, Apache Tomcat versions 10.0.0-M1 to 10.0.0, 9.0.0.M1 to
    9.0.41 and 8.5.0 to 8.5.61 could duplicate request headers and a limited amount of request body from one
    request to another meaning user A and user B could both see the results of user A's request.
    (CVE-2021-25122)

  - The fix for CVE-2020-9484 was incomplete. When using Apache Tomcat 10.0.0-M1 to 10.0.0, 9.0.0.M1 to
    9.0.41, 8.5.0 to 8.5.61 or 7.0.0. to 7.0.107 with a configuration edge case that was highly unlikely to be
    used, the Tomcat instance was still vulnerable to CVE-2020-9494. Note that both the previously published
    prerequisites for CVE-2020-9484 and the previously published mitigations for CVE-2020-9484 also apply to
    this issue. (CVE-2021-25329)

  - A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of
    a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue
    affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65. (CVE-2021-30640)

  - Apache Tomcat 10.0.0-M1 to 10.0.6, 9.0.0.M1 to 9.0.46 and 8.5.0 to 8.5.66 did not correctly parse the HTTP
    transfer-encoding request header in some circumstances leading to the possibility to request smuggling
    when used with a reverse proxy. Specifically: - Tomcat incorrectly ignored the transfer encoding header if
    the client declared it would only accept an HTTP/1.0 response; - Tomcat honoured the identify encoding;
    and - Tomcat did not ensure that, if present, the chunked encoding was the final encoding.
    (CVE-2021-33037)

  - Apache Tomcat 8.5.0 to 8.5.63, 9.0.0-M1 to 9.0.43 and 10.0.0-M1 to 10.0.2 did not properly validate
    incoming TLS packets. When Tomcat was configured to use NIO+OpenSSL or NIO2+OpenSSL for TLS, a specially
    crafted packet could be used to trigger an infinite loop resulting in a denial of service.
    (CVE-2021-41079)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5360-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30640");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-25122");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat9-embed-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat9-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat9-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat9-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat9-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat9-user");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libtomcat9-embed-java', 'pkgver': '9.0.16-3ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libtomcat9-java', 'pkgver': '9.0.16-3ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'tomcat9', 'pkgver': '9.0.16-3ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'tomcat9-admin', 'pkgver': '9.0.16-3ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'tomcat9-common', 'pkgver': '9.0.16-3ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'tomcat9-examples', 'pkgver': '9.0.16-3ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'tomcat9-user', 'pkgver': '9.0.16-3ubuntu0.18.04.2'},
    {'osver': '20.04', 'pkgname': 'libtomcat9-embed-java', 'pkgver': '9.0.31-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libtomcat9-java', 'pkgver': '9.0.31-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'tomcat9', 'pkgver': '9.0.31-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'tomcat9-admin', 'pkgver': '9.0.31-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'tomcat9-common', 'pkgver': '9.0.31-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'tomcat9-examples', 'pkgver': '9.0.31-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'tomcat9-user', 'pkgver': '9.0.31-1ubuntu0.2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtomcat9-embed-java / libtomcat9-java / tomcat9 / tomcat9-admin / etc');
}
