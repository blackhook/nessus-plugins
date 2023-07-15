#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:3922.
##

include('compat.inc');

if (description)
{
  script_id(177782);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id(
    "CVE-2023-29402",
    "CVE-2023-29403",
    "CVE-2023-29404",
    "CVE-2023-29405"
  );
  script_xref(name:"ALSA", value:"2023:3922");
  script_xref(name:"IAVB", value:"2023-B-0040");

  script_name(english:"AlmaLinux 8 : go-toolset:rhel8 (ALSA-2023:3922)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:3922 advisory.

  - The go command may generate unexpected code at build time when using cgo. This may result in unexpected
    behavior when running a go program which uses cgo. This may occur when running an untrusted module which
    contains directories with newline characters in their names. Modules which are retrieved using the go
    command, i.e. via go get, are not affected (modules retrieved using GOPATH-mode, i.e. GO111MODULE=off,
    may be affected). (CVE-2023-29402)

  - On Unix platforms, the Go runtime does not behave differently when a binary is run with the setuid/setgid
    bits. This can be dangerous in certain cases, such as when dumping memory state, or assuming the status of
    standard i/o file descriptors. If a setuid/setgid binary is executed with standard I/O file descriptors
    closed, opening any files can result in unexpected content being read or written with elevated privileges.
    Similarly, if a setuid/setgid program is terminated, either via panic or signal, it may leak the contents
    of its registers. (CVE-2023-29403)

  - The go command may execute arbitrary code at build time when using cgo. This may occur when running go
    get on a malicious module, or when running any other command which builds untrusted code. This is can by
    triggered by linker flags, specified via a #cgo LDFLAGS directive. The arguments for a number of flags
    which are non-optional are incorrectly considered optional, allowing disallowed flags to be smuggled
    through the LDFLAGS sanitization. This affects usage of both the gc and gccgo compilers. (CVE-2023-29404)

  - The go command may execute arbitrary code at build time when using cgo. This may occur when running go
    get on a malicious module, or when running any other command which builds untrusted code. This is can by
    triggered by linker flags, specified via a #cgo LDFLAGS directive. Flags containing embedded spaces are
    mishandled, allowing disallowed flags to be smuggled through the LDFLAGS sanitization by including them in
    the argument of another flag. This only affects usage of the gccgo compiler. (CVE-2023-29405)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-3922.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29405");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(668, 74, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:delve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:go-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/go-toolset');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:rhel8');
if ('rhel8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module go-toolset:' + module_ver);

var appstreams = {
    'go-toolset:rhel8': [
      {'reference':'delve-1.9.1-1.module_el8.8.0+3471+a62632a0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-docs-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-misc-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-race-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-race-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-src-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-tests-1.19.10-1.module_el8.8.0+3571+89db2ae0', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
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
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:rhel8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'delve / go-toolset / golang / golang-bin / golang-docs / etc');
}
