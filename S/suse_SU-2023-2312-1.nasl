#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2312-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(176517);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/31");

  script_cve_id(
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-24675",
    "CVE-2022-27536",
    "CVE-2022-27664",
    "CVE-2022-28131",
    "CVE-2022-28327",
    "CVE-2022-29526",
    "CVE-2022-29804",
    "CVE-2022-30580",
    "CVE-2022-30629",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30634",
    "CVE-2022-30635",
    "CVE-2022-32148",
    "CVE-2022-32189",
    "CVE-2022-41715",
    "CVE-2022-41716",
    "CVE-2022-41717",
    "CVE-2022-41720",
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2312-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : go1.18-openssl (SUSE-SU-2023:2312-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:2312-1 advisory.

  - Acceptance of some invalid Transfer-Encoding headers in the HTTP/1 client in net/http before Go 1.17.12
    and Go 1.18.4 allows HTTP request smuggling if combined with an intermediate server that also improperly
    fails to reject the header as invalid. (CVE-2022-1705)

  - Uncontrolled recursion in the Parse functions in go/parser before Go 1.17.12 and Go 1.18.4 allow an
    attacker to cause a panic due to stack exhaustion via deeply nested types or declarations. (CVE-2022-1962)

  - encoding/pem in Go before 1.17.9 and 1.18.x before 1.18.1 has a Decode stack overflow via a large amount
    of PEM data. (CVE-2022-24675)

  - Certificate.Verify in crypto/x509 in Go 1.18.x before 1.18.1 can be caused to panic on macOS when
    presented with certain malformed certificates. This allows a remote TLS server to cause a TLS client to
    panic. (CVE-2022-27536)

  - In net/http in Go before 1.18.6 and 1.19.x before 1.19.1, attackers can cause a denial of service because
    an HTTP/2 connection can hang during closing if shutdown were preempted by a fatal error. (CVE-2022-27664)

  - Uncontrolled recursion in Decoder.Skip in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker
    to cause a panic due to stack exhaustion via a deeply nested XML document. (CVE-2022-28131)

  - The generic P-256 feature in crypto/elliptic in Go before 1.17.9 and 1.18.x before 1.18.1 allows a panic
    via long scalar input. (CVE-2022-28327)

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

  - Incorrect conversion of certain invalid paths to valid, absolute paths in Clean in path/filepath before Go
    1.17.11 and Go 1.18.3 on Windows allows potential directory traversal attack. (CVE-2022-29804)

  - Code injection in Cmd.Start in os/exec before Go 1.17.11 and Go 1.18.3 allows execution of any binaries in
    the working directory named either ..com or ..exe by calling Cmd.Run, Cmd.Start, Cmd.Output, or
    Cmd.CombinedOutput when Cmd.Path is unset. (CVE-2022-30580)

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

  - Infinite loop in Read in crypto/rand before Go 1.17.11 and Go 1.18.3 on Windows allows attacker to cause
    an indefinite hang by passing a buffer larger than 1 << 32 - 1 bytes. (CVE-2022-30634)

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

  - Due to unsanitized NUL values, attackers may be able to maliciously set environment variables on Windows.
    In syscall.StartProcess and os/exec.Cmd, invalid environment variable values containing NUL values are not
    properly checked for. A malicious environment variable value can exploit this behavior to set a value for
    a different environment variable. For example, the environment variable string A=B\x00C=D sets the
    variables A=B and C=D. (CVE-2022-41716)

  - An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server
    connections contain a cache of HTTP header keys sent by the client. While the total number of entries in
    this cache is capped, an attacker sending very large keys can cause the server to allocate approximately
    64 MiB per open connection. (CVE-2022-41717)

  - On Windows, restricted files can be accessed via os.DirFS and http.Dir. The os.DirFS function and http.Dir
    type provide access to a tree of files rooted at a given directory. These functions permit access to
    Windows device files under that root. For example, os.DirFS(C:/tmp).Open(COM1) opens the COM1 device.
    Both os.DirFS and http.Dir only provide read-only filesystem access. In addition, on Windows, an os.DirFS
    for the directory (the root of the current drive) can permit a maliciously crafted path to escape from the
    drive and access any path on the system. With fix applied, the behavior of os.DirFS() has changed.
    Previously, an empty root was treated equivalently to /, so os.DirFS().Open(tmp) would open the path
    /tmp. This now returns an error. (CVE-2022-41720)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208491");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-May/015005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71268e09");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41716");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41725");
  script_set_attribute(attribute:"solution", value:
"Update the affected go1.18-openssl, go1.18-openssl-doc and / or go1.18-openssl-race packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29526");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30580");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.18-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.18-openssl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.18-openssl-race");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'go1.18-openssl-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-ESPOS-release-3', 'SLE_RT-release-15.3']},
    {'reference':'go1.18-openssl-doc-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-ESPOS-release-3', 'SLE_RT-release-15.3']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-ESPOS-release-3', 'SLE_RT-release-15.3']},
    {'reference':'go1.18-openssl-1.18.10.1-150000.1.9.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'go1.18-openssl-1.18.10.1-150000.1.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'go1.18-openssl-doc-1.18.10.1-150000.1.9.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'go1.18-openssl-doc-1.18.10.1-150000.1.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'go1.18-openssl-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'go1.18-openssl-doc-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'go1.18-openssl-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'go1.18-openssl-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'go1.18-openssl-doc-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'go1.18-openssl-doc-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'go1.18-openssl-1.18.10.1-150000.1.9.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.18-openssl-doc-1.18.10.1-150000.1.9.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.18-openssl-race-1.18.10.1-150000.1.9.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.18-openssl-1.18.10.1-150000.1.9.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'go1.18-openssl-doc-1.18.10.1-150000.1.9.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'go1.18-openssl / go1.18-openssl-doc / go1.18-openssl-race');
}
