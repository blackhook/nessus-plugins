#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:3083.
##

include('compat.inc');

if (description)
{
  script_id(176080);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_cve_id("CVE-2022-41724", "CVE-2022-41725");
  script_xref(name:"RLSA", value:"2023:3083");

  script_name(english:"Rocky Linux 8 : go-toolset:Rocky Linux8 (RLSA-2023:3083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2023:3083 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:3083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2167412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178492");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:delve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:delve-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:delve-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:go-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'delve-1.9.1-1.module+el8.8.0+1263+19d1a562', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'delve-debuginfo-1.9.1-1.module+el8.8.0+1263+19d1a562', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'delve-debugsource-1.9.1-1.module+el8.8.0+1263+19d1a562', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'go-toolset-1.19.6-1.module+el8.8.0+1263+19d1a562', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'go-toolset-1.19.6-1.module+el8.8.0+1263+19d1a562', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.6-1.module+el8.8.0+1263+19d1a562', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.6-1.module+el8.8.0+1263+19d1a562', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.6-1.module+el8.8.0+1263+19d1a562', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.6-1.module+el8.8.0+1263+19d1a562', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-docs-1.19.6-1.module+el8.8.0+1263+19d1a562', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-misc-1.19.6-1.module+el8.8.0+1263+19d1a562', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-race-1.19.6-1.module+el8.8.0+1263+19d1a562', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-src-1.19.6-1.module+el8.8.0+1263+19d1a562', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-tests-1.19.6-1.module+el8.8.0+1263+19d1a562', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'delve / delve-debuginfo / delve-debugsource / go-toolset / golang / etc');
}
