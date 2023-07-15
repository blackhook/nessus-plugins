#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2023-1731.
##

include('compat.inc');

if (description)
{
  script_id(174620);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id(
    "CVE-2022-30580",
    "CVE-2022-30634",
    "CVE-2022-32189",
    "CVE-2022-41717",
    "CVE-2022-41722",
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-24532",
    "CVE-2023-24534",
    "CVE-2023-24536",
    "CVE-2023-24537",
    "CVE-2023-24538"
  );
  script_xref(name:"IAVB", value:"2022-B-0059-S");
  script_xref(name:"IAVB", value:"2023-B-0012-S");
  script_xref(name:"IAVB", value:"2023-B-0022-S");

  script_name(english:"Amazon Linux AMI : golang (ALAS-2023-1731)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of golang installed on the remote host is prior to 1.18.6-1.43. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2023-1731 advisory.

  - Code injection in Cmd.Start in os/exec before Go 1.17.11 and Go 1.18.3 allows execution of any binaries in
    the working directory named either ..com or ..exe by calling Cmd.Run, Cmd.Start, Cmd.Output, or
    Cmd.CombinedOutput when Cmd.Path is unset. (CVE-2022-30580)

  - Infinite loop in Read in crypto/rand before Go 1.17.11 and Go 1.18.3 on Windows allows attacker to cause
    an indefinite hang by passing a buffer larger than 1 << 32 - 1 bytes. (CVE-2022-30634)

  - A too-short encoded message can cause a panic in Float.GobDecode and Rat GobDecode in math/big in Go
    before 1.17.13 and 1.18.5, potentially allowing a denial of service. (CVE-2022-32189)

  - An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server
    connections contain a cache of HTTP header keys sent by the client. While the total number of entries in
    this cache is capped, an attacker sending very large keys can cause the server to allocate approximately
    64 MiB per open connection. (CVE-2022-41717)

  - A path traversal vulnerability exists in filepath.Clean on Windows. On Windows, the filepath.Clean
    function could transform an invalid path such as a/../c:/b into the valid path c:\b. This
    transformation of a relative (if invalid) path into an absolute path could enable a directory traversal
    attack. After fix, the filepath.Clean function transforms this path into the relative (but still invalid)
    path .\c:\b. (CVE-2022-41722)

  - A maliciously crafted HTTP/2 stream could cause excessive CPU consumption in the HPACK decoder, sufficient
    to cause a denial of service from a small number of small requests. (CVE-2022-41723)

  - Large handshake records may cause panics in crypto/tls. Both clients and servers may send large TLS
    handshake records which cause servers and clients, respectively, to panic when attempting to construct
    responses. This affects all TLS 1.3 clients, TLS 1.2 clients which explicitly enable session resumption
    (by setting Config.ClientSessionCache to a non-nil value), and TLS 1.3 servers which request client
    certificates (by setting Config.ClientAuth >= RequestClientCert). (CVE-2022-41724)

  - A denial of service is possible from excessive resource consumption in net/http and mime/multipart.
    Multipart form parsing with mime/multipart.Reader.ReadForm can consume largely unlimited amounts of memory
    and disk files. This also affects form parsing in the net/http package with the Request methods FormFile,
    FormValue, ParseMultipartForm, and PostFormValue. ReadForm takes a maxMemory parameter, and is documented
    as storing up to maxMemory bytes +10MB (reserved for non-file parts) in memory. File parts which cannot
    be stored in memory are stored on disk in temporary files. The unconfigurable 10MB reserved for non-file
    parts is excessively large and can potentially open a denial of service vector on its own. However,
    ReadForm did not properly account for all memory consumed by a parsed form, such as map entry overhead,
    part names, and MIME headers, permitting a maliciously crafted form to consume well over 10MB. In
    addition, ReadForm contained no limit on the number of disk files created, permitting a relatively small
    request body to create a large number of disk temporary files. With fix, ReadForm now properly accounts
    for various forms of memory overhead, and should now stay within its documented limit of 10MB + maxMemory
    bytes of memory consumption. Users should still be aware that this limit is high and may still be
    hazardous. In addition, ReadForm now creates at most one on-disk temporary file, combining multiple form
    parts into a single temporary file. The mime/multipart.File interface type's documentation states, If
    stored on disk, the File's underlying concrete type will be an *os.File.. This is no longer the case when
    a form contains more than one file part, due to this coalescing of parts into a single file. The previous
    behavior of using distinct files for each form part may be reenabled with the environment variable
    GODEBUG=multipartfiles=distinct. Users should be aware that multipart.ReadForm and the http.Request
    methods that call it do not limit the amount of disk consumed by temporary files. Callers can limit the
    size of form data with http.MaxBytesReader. (CVE-2022-41725)

  - The ScalarMult and ScalarBaseMult methods of the P256 Curve may return an incorrect result if called with
    some specific unreduced scalars (a scalar larger than the order of the curve). This does not impact usages
    of crypto/ecdsa or crypto/ecdh. (CVE-2023-24532)

  - HTTP and MIME header parsing can allocate large amounts of memory, even when parsing small inputs,
    potentially leading to a denial of service. Certain unusual patterns of input data can cause the common
    function used to parse HTTP and MIME headers to allocate substantially more memory than required to hold
    the parsed headers. An attacker can exploit this behavior to cause an HTTP server to allocate large
    amounts of memory from a small request, potentially leading to memory exhaustion and a denial of service.
    With fix, header parsing now correctly allocates only the memory required to hold parsed headers.
    (CVE-2023-24534)

  - Multipart form parsing can consume large amounts of CPU and memory when processing form inputs containing
    very large numbers of parts. This stems from several causes: 1. mime/multipart.Reader.ReadForm limits the
    total memory a parsed multipart form can consume. ReadForm can undercount the amount of memory consumed,
    leading it to accept larger inputs than intended. 2. Limiting total memory does not account for increased
    pressure on the garbage collector from large numbers of small allocations in forms with many parts. 3.
    ReadForm can allocate a large number of short-lived buffers, further increasing pressure on the garbage
    collector. The combination of these factors can permit an attacker to cause an program that parses
    multipart forms to consume large amounts of CPU and memory, potentially resulting in a denial of service.
    This affects programs that use mime/multipart.Reader.ReadForm, as well as form parsing in the net/http
    package with the Request methods FormFile, FormValue, ParseMultipartForm, and PostFormValue. With fix,
    ReadForm now does a better job of estimating the memory consumption of parsed forms, and performs many
    fewer short-lived allocations. In addition, the fixed mime/multipart.Reader imposes the following limits
    on the size of parsed forms: 1. Forms parsed with ReadForm may contain no more than 1000 parts. This limit
    may be adjusted with the environment variable GODEBUG=multipartmaxparts=. 2. Form parts parsed with
    NextPart and NextRawPart may contain no more than 10,000 header fields. In addition, forms parsed with
    ReadForm may contain no more than 10,000 header fields across all parts. This limit may be adjusted with
    the environment variable GODEBUG=multipartmaxheaders=. (CVE-2023-24536)

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
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2023-1731.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30580.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30634.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32189.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41717.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41722.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41723.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41724.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41725.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24532.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24534.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24536.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24537.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24538.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update golang' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24538");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'golang-1.18.6-1.43.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.18.6-1.43.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.18.6-1.43.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.18.6-1.43.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-docs-1.18.6-1.43.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-misc-1.18.6-1.43.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-race-1.18.6-1.43.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.18.6-1.43.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.18.6-1.43.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-src-1.18.6-1.43.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-tests-1.18.6-1.43.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang / golang-bin / golang-docs / etc");
}