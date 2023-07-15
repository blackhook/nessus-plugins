#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0118. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127360);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2005-1268",
    "CVE-2005-2088",
    "CVE-2005-2700",
    "CVE-2005-2728",
    "CVE-2005-3352",
    "CVE-2005-3357",
    "CVE-2009-3555",
    "CVE-2010-1452",
    "CVE-2011-3638",
    "CVE-2016-8743",
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-7668",
    "CVE-2017-7679",
    "CVE-2017-9788",
    "CVE-2017-9798"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : httpd Multiple Vulnerabilities (NS-SA-2019-0118)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has httpd packages installed that are affected by multiple
vulnerabilities:

  - Off-by-one error in the mod_ssl Certificate Revocation
    List (CRL) verification callback in Apache, when
    configured to use a CRL, allows remote attackers to
    cause a denial of service (child process crash) via a
    CRL that causes a buffer overflow of one null byte.
    (CVE-2005-1268)

  - The Apache HTTP server before 1.3.34, and 2.0.x before
    2.0.55, when acting as an HTTP proxy, allows remote
    attackers to poison the web cache, bypass web
    application firewall protection, and conduct XSS attacks
    via an HTTP request with both a Transfer-Encoding:
    chunked header and a Content-Length header, which
    causes Apache to incorrectly handle and forward the body
    of the request in a way that causes the receiving server
    to process it as a separate HTTP request, aka HTTP
    Request Smuggling. (CVE-2005-2088)

  - ssl_engine_kernel.c in mod_ssl before 2.8.24, when using
    SSLVerifyClient optional in the global virtual host
    configuration, does not properly enforce
    SSLVerifyClient require in a per-location context,
    which allows remote attackers to bypass intended access
    restrictions. (CVE-2005-2700)

  - The byte-range filter in Apache 2.0 before 2.0.54 allows
    remote attackers to cause a denial of service (memory
    consumption) via an HTTP header with a large Range
    field. (CVE-2005-2728)

  - Cross-site scripting (XSS) vulnerability in the mod_imap
    module of Apache httpd before 1.3.35-dev and Apache
    httpd 2.0.x before 2.0.56-dev allows remote attackers to
    inject arbitrary web script or HTML via the Referer when
    using image maps. (CVE-2005-3352)

  - mod_ssl in Apache 2.0 up to 2.0.55, when configured with
    an SSL vhost with access control and a custom error 400
    error page, allows remote attackers to cause a denial of
    service (application crash) via a non-SSL request to an
    SSL port, which triggers a NULL pointer dereference.
    (CVE-2005-3357)

  - The TLS protocol, and the SSL protocol 3.0 and possibly
    earlier, as used in Microsoft Internet Information
    Services (IIS) 7.0, mod_ssl in the Apache HTTP Server
    2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS 2.8.5
    and earlier, Mozilla Network Security Services (NSS)
    3.12.4 and earlier, multiple Cisco products, and other
    products, does not properly associate renegotiation
    handshakes with an existing connection, which allows
    man-in-the-middle attackers to insert data into HTTPS
    sessions, and possibly other types of sessions protected
    by TLS or SSL, by sending an unauthenticated request
    that is processed retroactively by a server in a post-
    renegotiation context, related to a plaintext
    injection attack, aka the Project Mogul issue.
    (CVE-2009-3555)

  - The (1) mod_cache and (2) mod_dav modules in the Apache
    HTTP Server 2.2.x before 2.2.16 allow remote attackers
    to cause a denial of service (process crash) via a
    request that lacks a path. (CVE-2010-1452)

  - fs/ext4/extents.c in the Linux kernel before 3.0 does
    not mark a modified extent as dirty in certain cases of
    extent splitting, which allows local users to cause a
    denial of service (system crash) via vectors involving
    ext4 umount and mount operations. (CVE-2011-3638)

  - It was discovered that the HTTP parser in httpd
    incorrectly allowed certain characters not permitted by
    the HTTP protocol specification to appear unencoded in
    HTTP request headers. If httpd was used in conjunction
    with a proxy or backend server that interpreted those
    characters differently, a remote attacker could possibly
    use this flaw to inject data into HTTP responses,
    resulting in proxy cache poisoning. (CVE-2016-8743)

  - It was discovered that the use of httpd's
    ap_get_basic_auth_pw() API function outside of the
    authentication phase could lead to authentication
    bypass. A remote attacker could possibly use this flaw
    to bypass required authentication if the API was used
    incorrectly by one of the modules used by httpd.
    (CVE-2017-3167)

  - A NULL pointer dereference flaw was found in the httpd's
    mod_ssl module. A remote attacker could use this flaw to
    cause an httpd child process to crash if another module
    used by httpd called a certain API function during the
    processing of an HTTPS request. (CVE-2017-3169)

  - A buffer over-read flaw was found in the httpd's
    ap_find_token() function. A remote attacker could use
    this flaw to cause httpd child process to crash via a
    specially crafted HTTP request. (CVE-2017-7668)

  - A buffer over-read flaw was found in the httpd's
    mod_mime module. A user permitted to modify httpd's MIME
    configuration could use this flaw to cause httpd child
    process to crash. (CVE-2017-7679)

  - It was discovered that the httpd's mod_auth_digest
    module did not properly initialize memory before using
    it when processing certain headers related to digest
    authentication. A remote attacker could possibly use
    this flaw to disclose potentially sensitive information
    or cause httpd child process to crash by sending
    specially crafted requests to a server. (CVE-2017-9788)

  - A use-after-free flaw was found in the way httpd handled
    invalid and previously unregistered HTTP methods
    specified in the Limit directive used in an .htaccess
    file. A remote attacker could possibly use this flaw to
    disclose portions of the server memory, or cause httpd
    child process to crash. (CVE-2017-9798)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0118");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL httpd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-2700");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7679");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "httpd-2.2.15-60.el6.centos.6",
    "httpd-devel-2.2.15-60.el6.centos.6",
    "httpd-manual-2.2.15-60.el6.centos.6",
    "httpd-tools-2.2.15-60.el6.centos.6",
    "mod_ssl-2.2.15-60.el6.centos.6"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
