#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177955);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2022-41723", "CVE-2022-41724", "CVE-2022-41725");
  script_xref(name:"IAVB", value:"2023-B-0012-S");

  script_name(english:"EulerOS 2.0 SP11 : golang (EulerOS-SA-2023-2268)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the golang packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

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
    as storing 'up to maxMemory bytes +10MB (reserved for non-file parts) in memory'. File parts which cannot
    be stored in memory are stored on disk in temporary files. The unconfigurable 10MB reserved for non-file
    parts is excessively large and can potentially open a denial of service vector on its own. However,
    ReadForm did not properly account for all memory consumed by a parsed form, such as map entry overhead,
    part names, and MIME headers, permitting a maliciously crafted form to consume well over 10MB. In
    addition, ReadForm contained no limit on the number of disk files created, permitting a relatively small
    request body to create a large number of disk temporary files. With fix, ReadForm now properly accounts
    for various forms of memory overhead, and should now stay within its documented limit of 10MB + maxMemory
    bytes of memory consumption. Users should still be aware that this limit is high and may still be
    hazardous. In addition, ReadForm now creates at most one on-disk temporary file, combining multiple form
    parts into a single temporary file. The mime/multipart.File interface type's documentation states, 'If
    stored on disk, the File's underlying concrete type will be an *os.File.'. This is no longer the case when
    a form contains more than one file part, due to this coalescing of parts into a single file. The previous
    behavior of using distinct files for each form part may be reenabled with the environment variable
    GODEBUG=multipartfiles=distinct. Users should be aware that multipart.ReadForm and the http.Request
    methods that call it do not limit the amount of disk consumed by temporary files. Callers can limit the
    size of form data with http.MaxBytesReader. (CVE-2022-41725)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2268
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6289e162");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41725");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang-help");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "golang-1.17.3-1.h14.eulerosv2r11",
  "golang-devel-1.17.3-1.h14.eulerosv2r11",
  "golang-help-1.17.3-1.h14.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang");
}
