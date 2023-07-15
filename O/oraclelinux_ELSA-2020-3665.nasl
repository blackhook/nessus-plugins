##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-3665.
##

include('compat.inc');

if (description)
{
  script_id(140524);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/11");

  script_cve_id("CVE-2020-14040", "CVE-2020-15586", "CVE-2020-16845");
  script_xref(name:"IAVB", value:"2020-B-0060-S");

  script_name(english:"Oracle Linux 8 : go-toolset:ol8 (ELSA-2020-3665)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-3665 advisory.

  - Go before 1.13.15 and 14.x before 1.14.7 can have an infinite read loop in ReadUvarint and ReadVarint in
    encoding/binary via invalid inputs. (CVE-2020-16845)

  - The x/text package before 0.3.3 for Go has a vulnerability in encoding/unicode that could lead to the
    UTF-16 decoder entering an infinite loop, causing the program to crash or run out of memory. An attacker
    could provide a single byte to a UTF16 decoder instantiated with UseBOM or ExpectBOM to trigger an
    infinite loop if the String function on the Decoder is called, or the Decoder is passed to
    golang.org/x/text/transform.String. (CVE-2020-14040)

  - Go before 1.13.13 and 1.14.x before 1.14.5 has a data race in some net/http servers, as demonstrated by
    the httputil.ReverseProxy Handler, because it reads a request body and writes a response at the same time.
    (CVE-2020-15586)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-3665.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16845");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/go-toolset');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:ol8');
if ('ol8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module go-toolset:' + module_ver);

appstreams = {
    'go-toolset:ol8': [
      {'reference':'delve-1.3.2-3.0.1.module+el8.2.0+5587+55f012d0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-docs-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-misc-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-race-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-src-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-tests-1.13.15-1.module+el8.2.0+7788+3ff8dc7f', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:ol8');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'delve / go-toolset / golang / etc');
}
