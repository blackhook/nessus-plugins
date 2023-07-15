#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-048.
##

include('compat.inc');

if (description)
{
  script_id(173069);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id(
    "CVE-2021-33196",
    "CVE-2021-38297",
    "CVE-2021-41771",
    "CVE-2021-41772",
    "CVE-2021-44716",
    "CVE-2021-44717",
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-2879",
    "CVE-2022-24675",
    "CVE-2022-27191",
    "CVE-2022-27664",
    "CVE-2022-28131",
    "CVE-2022-28327",
    "CVE-2022-29526",
    "CVE-2022-30629",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30635",
    "CVE-2022-32148",
    "CVE-2022-32189",
    "CVE-2022-32190",
    "CVE-2022-41715",
    "CVE-2022-41716"
  );
  script_xref(name:"IAVB", value:"2022-B-0046-S");
  script_xref(name:"IAVB", value:"2022-B-0042-S");
  script_xref(name:"IAVB", value:"2021-B-0069-S");
  script_xref(name:"IAVB", value:"2022-B-0025-S");

  script_name(english:"Amazon Linux 2023 : golang, golang-bin, golang-misc (ALAS2023-2023-048)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-048 advisory.

  - In archive/zip in Go before 1.15.13 and 1.16.x before 1.16.5, a crafted file count (in an archive's
    header) can cause a NewReader or OpenReader panic. (CVE-2021-33196)

  - Go before 1.16.9 and 1.17.x before 1.17.2 has a Buffer Overflow via large arguments in a function
    invocation from a WASM module, when GOARCH=wasm GOOS=js is used. (CVE-2021-38297)

  - ImportedSymbols in debug/macho (for Open or OpenFat) in Go before 1.16.10 and 1.17.x before 1.17.3
    Accesses a Memory Location After the End of a Buffer, aka an out-of-bounds slice situation.
    (CVE-2021-41771)

  - Go before 1.16.10 and 1.17.x before 1.17.3 allows an archive/zip Reader.Open panic via a crafted ZIP
    archive containing an invalid name or an empty filename field. (CVE-2021-41772)

  - net/http in Go before 1.16.12 and 1.17.x before 1.17.5 allows uncontrolled memory consumption in the
    header canonicalization cache via HTTP/2 requests. (CVE-2021-44716)

  - Go before 1.16.12 and 1.17.x before 1.17.5 on UNIX allows write operations to an unintended file or
    unintended network connection as a consequence of erroneous closing of file descriptor 0 after file-
    descriptor exhaustion. (CVE-2021-44717)

  - Acceptance of some invalid Transfer-Encoding headers in the HTTP/1 client in net/http before Go 1.17.12
    and Go 1.18.4 allows HTTP request smuggling if combined with an intermediate server that also improperly
    fails to reject the header as invalid. (CVE-2022-1705)

  - Uncontrolled recursion in the Parse functions in go/parser before Go 1.17.12 and Go 1.18.4 allow an
    attacker to cause a panic due to stack exhaustion via deeply nested types or declarations. (CVE-2022-1962)

  - Authorization Bypass Through User-Controlled Key in GitHub repository emicklei/go-restful prior to v3.8.0.
    (CVE-2022-1996)

  - encoding/pem in Go before 1.17.9 and 1.18.x before 1.18.1 has a Decode stack overflow via a large amount
    of PEM data. (CVE-2022-24675)

  - The golang.org/x/crypto/ssh package before 0.0.0-20220314234659-1baeb1ce4c0b for Go allows an attacker to
    crash a server in certain circumstances involving AddHostKey. (CVE-2022-27191)

  - In net/http in Go before 1.18.6 and 1.19.x before 1.19.1, attackers can cause a denial of service because
    an HTTP/2 connection can hang during closing if shutdown were preempted by a fatal error. (CVE-2022-27664)

  - Uncontrolled recursion in Decoder.Skip in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker
    to cause a panic due to stack exhaustion via a deeply nested XML document. (CVE-2022-28131)

  - The generic P-256 feature in crypto/elliptic in Go before 1.17.9 and 1.18.x before 1.18.1 allows a panic
    via long scalar input. (CVE-2022-28327)

  - Reader.Read does not set a limit on the maximum size of file headers. A maliciously crafted archive could
    cause Read to allocate unbounded amounts of memory, potentially causing resource exhaustion or panics.
    After fix, Reader.Read limits the maximum size of header blocks to 1 MiB. (CVE-2022-2879)

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

  - JoinPath and URL.JoinPath do not remove ../ path elements appended to a relative path. For example,
    JoinPath(https://go.dev, ../go) returns the URL https://go.dev/../go, despite the JoinPath
    documentation stating that ../ path elements are removed from the result. (CVE-2022-32190)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-048.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-33196.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38297.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41771.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41772.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44716.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44717.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1705.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1962.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24675.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27191.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27664.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-28131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-28327.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2879.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-29526.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30629.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30630.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30631.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30632.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30633.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30635.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32148.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32189.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32190.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41715.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41716.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update golang --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38297");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'golang-1.19.3-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.3-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.3-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.3-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.3-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.3-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-docs-1.19.3-2.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-misc-1.19.3-2.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-race-1.19.3-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.19.3-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.19.3-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.19.3-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-src-1.19.3-2.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-tests-1.19.3-2.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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