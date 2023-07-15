#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6038-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174750);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-27664",
    "CVE-2022-28131",
    "CVE-2022-29526",
    "CVE-2022-30629",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30635",
    "CVE-2022-32148",
    "CVE-2022-32189",
    "CVE-2022-41715",
    "CVE-2022-41717",
    "CVE-2023-24534",
    "CVE-2023-24537",
    "CVE-2023-24538"
  );
  script_xref(name:"USN", value:"6038-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : Go vulnerabilities (USN-6038-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6038-1 advisory.

  - Acceptance of some invalid Transfer-Encoding headers in the HTTP/1 client in net/http before Go 1.17.12
    and Go 1.18.4 allows HTTP request smuggling if combined with an intermediate server that also improperly
    fails to reject the header as invalid. (CVE-2022-1705)

  - Uncontrolled recursion in the Parse functions in go/parser before Go 1.17.12 and Go 1.18.4 allow an
    attacker to cause a panic due to stack exhaustion via deeply nested types or declarations. (CVE-2022-1962)

  - In net/http in Go before 1.18.6 and 1.19.x before 1.19.1, attackers can cause a denial of service because
    an HTTP/2 connection can hang during closing if shutdown were preempted by a fatal error. (CVE-2022-27664)

  - Uncontrolled recursion in Decoder.Skip in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker
    to cause a panic due to stack exhaustion via a deeply nested XML document. (CVE-2022-28131)

  - Reader.Read does not set a limit on the maximum size of file headers. A maliciously crafted archive could
    cause Read to allocate unbounded amounts of memory, potentially causing resource exhaustion or panics.
    After fix, Reader.Read limits the maximum size of header blocks to 1 MiB. (CVE-2022-2879)

  - Requests forwarded by ReverseProxy include the raw query parameters from the inbound request, including
    unparseable parameters rejected by net/http. This could permit query parameter smuggling when a Go proxy
    forwards a parameter with an unparseable value. After fix, ReverseProxy sanitizes the query parameters in
    the forwarded query when the outbound request's Form field is set after the ReverseProxy. Director
    function returns, indicating that the proxy has parsed the query parameters. Proxies which do not parse
    query parameters continue to forward the original query parameters unchanged. (CVE-2022-2880)

  - Go before 1.17.10 and 1.18.x before 1.18.2 has Incorrect Privilege Assignment. When called with a non-zero
    flags parameter, the Faccessat function could incorrectly report that a file is accessible.
    (CVE-2022-29526)

  - Non-random values for ticket_age_add in session tickets in crypto/tls before Go 1.17.11 and Go 1.18.3
    allow an attacker that can observe TLS handshakes to correlate successive connections by comparing ticket
    ages during session resumption. (CVE-2022-30629)

  - Uncontrolled recursion in Glob in io/fs before Go 1.17.12 and Go 1.18.4 allows an attacker to cause a
    panic due to stack exhaustion via a path which contains a large number of path separators.
    (CVE-2022-30630)

  - Uncontrolled recursion in Reader.Read in compress/gzip before Go 1.17.12 and Go 1.18.4 allows an attacker
    to cause a panic due to stack exhaustion via an archive containing a large number of concatenated 0-length
    compressed files. (CVE-2022-30631)

  - Uncontrolled recursion in Glob in path/filepath before Go 1.17.12 and Go 1.18.4 allows an attacker to
    cause a panic due to stack exhaustion via a path containing a large number of path separators.
    (CVE-2022-30632)

  - Uncontrolled recursion in Unmarshal in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker to
    cause a panic due to stack exhaustion via unmarshalling an XML document into a Go struct which has a
    nested field that uses the 'any' field tag. (CVE-2022-30633)

  - Uncontrolled recursion in Decoder.Decode in encoding/gob before Go 1.17.12 and Go 1.18.4 allows an
    attacker to cause a panic due to stack exhaustion via a message which contains deeply nested structures.
    (CVE-2022-30635)

  - Improper exposure of client IP addresses in net/http before Go 1.17.12 and Go 1.18.4 can be triggered by
    calling httputil.ReverseProxy.ServeHTTP with a Request.Header map containing a nil value for the
    X-Forwarded-For header, which causes ReverseProxy to set the client IP as the value of the X-Forwarded-For
    header. (CVE-2022-32148)

  - A too-short encoded message can cause a panic in Float.GobDecode and Rat GobDecode in math/big in Go
    before 1.17.13 and 1.18.5, potentially allowing a denial of service. (CVE-2022-32189)

  - Programs which compile regular expressions from untrusted sources may be vulnerable to memory exhaustion
    or denial of service. The parsed regexp representation is linear in the size of the input, but in some
    cases the constant factor can be as high as 40,000, making relatively small regexps consume much larger
    amounts of memory. After fix, each regexp being parsed is limited to a 256 MB memory footprint. Regular
    expressions whose representation would use more space than that are rejected. Normal use of regular
    expressions is unaffected. (CVE-2022-41715)

  - An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server
    connections contain a cache of HTTP header keys sent by the client. While the total number of entries in
    this cache is capped, an attacker sending very large keys can cause the server to allocate approximately
    64 MiB per open connection. (CVE-2022-41717)

  - HTTP and MIME header parsing can allocate large amounts of memory, even when parsing small inputs,
    potentially leading to a denial of service. Certain unusual patterns of input data can cause the common
    function used to parse HTTP and MIME headers to allocate substantially more memory than required to hold
    the parsed headers. An attacker can exploit this behavior to cause an HTTP server to allocate large
    amounts of memory from a small request, potentially leading to memory exhaustion and a denial of service.
    With fix, header parsing now correctly allocates only the memory required to hold parsed headers.
    (CVE-2023-24534)

  - Calling any of the Parse functions on Go source code which contains //line directives with very large line
    numbers can cause an infinite loop due to integer overflow. (CVE-2023-24537)

  - Templates do not properly consider backticks (`) as Javascript string delimiters, and do not escape them
    as expected. Backticks are used, since ES6, for JS template literals. If a template contains a Go template
    action within a Javascript template literal, the contents of the action can be used to terminate the
    literal, injecting arbitrary Javascript code into the Go template. As ES6 template literals are rather
    complex, and themselves can do string interpolation, the decision was made to simply disallow Go template
    actions from being used inside of them (e.g. var a = {{.}}), since there is no obviously safe way to
    allow this behavior. This takes the same approach as github.com/google/safehtml. With fix, Template.Parse
    returns an Error when it encounters templates like this, with an ErrorCode of value 12. This ErrorCode is
    currently unexported, but will be exported in the release of Go 1.21. Users who rely on the previous
    behavior can re-enable it using the GODEBUG flag jstmpllitinterp=1, with the caveat that backticks will
    now be escaped. This should be used with caution. (CVE-2023-24538)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6038-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-1.18, golang-1.18-go and / or golang-1.18-src packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29526");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-24538");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.18-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.18-src");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1~18.04.4'},
    {'osver': '20.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1~20.04.2'},
    {'osver': '22.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-1.18 / golang-1.18-go / golang-1.18-src');
}
