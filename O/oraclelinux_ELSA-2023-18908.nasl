#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-18908.
##

include('compat.inc');

if (description)
{
  script_id(172239);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id(
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-27664",
    "CVE-2022-32190",
    "CVE-2022-41715",
    "CVE-2022-41716",
    "CVE-2022-41717",
    "CVE-2022-41720"
  );
  script_xref(name:"IAVB", value:"2022-B-0042-S");
  script_xref(name:"IAVB", value:"2022-B-0059-S");
  script_xref(name:"IAVB", value:"2022-B-0046-S");

  script_name(english:"Oracle Linux 8 : ol8addon (ELSA-2023-18908)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-18908 advisory.

  - Reader.Read does not set a limit on the maximum size of file headers. A maliciously crafted archive could
    cause Read to allocate unbounded amounts of memory, potentially causing resource exhaustion or panics.
    After fix, Reader.Read limits the maximum size of header blocks to 1 MiB. (CVE-2022-2879)

  - On Windows, restricted files can be accessed via os.DirFS and http.Dir. The os.DirFS function and http.Dir
    type provide access to a tree of files rooted at a given directory. These functions permit access to
    Windows device files under that root. For example, os.DirFS(C:/tmp).Open(COM1) opens the COM1 device.
    Both os.DirFS and http.Dir only provide read-only filesystem access. In addition, on Windows, an os.DirFS
    for the directory (the root of the current drive) can permit a maliciously crafted path to escape from the
    drive and access any path on the system. With fix applied, the behavior of os.DirFS() has changed.
    Previously, an empty root was treated equivalently to /, so os.DirFS().Open(tmp) would open the path
    /tmp. This now returns an error. (CVE-2022-41720)

  - Due to unsanitized NUL values, attackers may be able to maliciously set environment variables on Windows.
    In syscall.StartProcess and os/exec.Cmd, invalid environment variable values containing NUL values are not
    properly checked for. A malicious environment variable value can exploit this behavior to set a value for
    a different environment variable. For example, the environment variable string A=B\x00C=D sets the
    variables A=B and C=D. (CVE-2022-41716)

  - JoinPath and URL.JoinPath do not remove ../ path elements appended to a relative path. For example,
    JoinPath(https://go.dev, ../go) returns the URL https://go.dev/../go, despite the JoinPath
    documentation stating that ../ path elements are removed from the result. (CVE-2022-32190)

  - Requests forwarded by ReverseProxy include the raw query parameters from the inbound request, including
    unparseable parameters rejected by net/http. This could permit query parameter smuggling when a Go proxy
    forwards a parameter with an unparseable value. After fix, ReverseProxy sanitizes the query parameters in
    the forwarded query when the outbound request's Form field is set after the ReverseProxy. Director
    function returns, indicating that the proxy has parsed the query parameters. Proxies which do not parse
    query parameters continue to forward the original query parameters unchanged. (CVE-2022-2880)

  - An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server
    connections contain a cache of HTTP header keys sent by the client. While the total number of entries in
    this cache is capped, an attacker sending very large keys can cause the server to allocate approximately
    64 MiB per open connection. (CVE-2022-41717)

  - In net/http in Go before 1.18.6 and 1.19.x before 1.19.1, attackers can cause a denial of service because
    an HTTP/2 connection can hang during closing if shutdown were preempted by a fatal error. (CVE-2022-27664)

  - Programs which compile regular expressions from untrusted sources may be vulnerable to memory exhaustion
    or denial of service. The parsed regexp representation is linear in the size of the input, but in some
    cases the constant factor can be as high as 40,000, making relatively small regexps consume much larger
    amounts of memory. After fix, each regexp being parsed is limited to a 256 MB memory footprint. Regular
    expressions whose representation would use more space than that are rejected. Normal use of regular
    expressions is unaffected. (CVE-2022-41715)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-18908.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41720");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:delve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:go-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-tests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'delve-1.9.1-1.0.1.module+el8.7.0+20922+47ac84ba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'delve-1.9.1-1.0.1.module+el8.7.0+20922+47ac84ba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'go-toolset-1.19.4-1.module+el8.7.0+20922+47ac84ba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'go-toolset-1.19.4-1.module+el8.7.0+20922+47ac84ba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.4-2.0.1.module+el8.7.0+20922+47ac84ba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.4-2.0.1.module+el8.7.0+20922+47ac84ba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.4-2.0.1.module+el8.7.0+20922+47ac84ba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.4-2.0.1.module+el8.7.0+20922+47ac84ba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-docs-1.19.4-2.0.1.module+el8.7.0+20922+47ac84ba', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-misc-1.19.4-2.0.1.module+el8.7.0+20922+47ac84ba', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-race-1.19.4-2.0.1.module+el8.7.0+20922+47ac84ba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-src-1.19.4-2.0.1.module+el8.7.0+20922+47ac84ba', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-tests-1.19.4-2.0.1.module+el8.7.0+20922+47ac84ba', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'delve / go-toolset / golang / etc');
}
