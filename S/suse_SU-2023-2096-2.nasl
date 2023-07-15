#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2096-2. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177502);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id("CVE-2022-24823", "CVE-2022-41881", "CVE-2022-41915");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2096-2");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : netty, netty-tcnative (SUSE-SU-2023:2096-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:2096-2 advisory.

  - Netty is an open-source, asynchronous event-driven network application framework. The package
    `io.netty:netty-codec-http` prior to version 4.1.77.Final contains an insufficient fix for CVE-2021-21290.
    When Netty's multipart decoders are used local information disclosure can occur via the local system
    temporary directory if temporary storing uploads on the disk is enabled. This only impacts applications
    running on Java version 6 and lower. Additionally, this vulnerability impacts code running on Unix-like
    systems, and very old versions of Mac OSX and Windows as they all share the system temporary directory
    between all users. Version 4.1.77.Final contains a patch for this vulnerability. As a workaround, specify
    one's own `java.io.tmpdir` when starting the JVM or use DefaultHttpDataFactory.setBaseDir(...) to set the
    directory to something that is only readable by the current user. (CVE-2022-24823)

  - Netty project is an event-driven asynchronous network application framework. In versions prior to
    4.1.86.Final, a StackOverflowError can be raised when parsing a malformed crafted message due to an
    infinite recursion. This issue is patched in version 4.1.86.Final. There is no workaround, except using a
    custom HaProxyMessageDecoder. (CVE-2022-41881)

  - Netty project is an event-driven asynchronous network application framework. Starting in version
    4.1.83.Final and prior to 4.1.86.Final, when calling `DefaultHttpHeadesr.set` with an _iterator_ of
    values, header value validation was not performed, allowing malicious header values in the iterator to
    perform HTTP Response Splitting. This issue has been patched in version 4.1.86.Final. Integrators can work
    around the issue by changing the `DefaultHttpHeaders.set(CharSequence, Iterator<?>)` call, into a
    `remove()` call, and call `add()` in a loop over the iterator of values. (CVE-2022-41915)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206379");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-June/029968.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41915");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24823");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41915");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netty-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netty-poms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netty-tcnative");
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
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'netty-4.1.90-150200.4.14.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'netty-4.1.90-150200.4.14.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'netty-javadoc-4.1.90-150200.4.14.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'netty-javadoc-4.1.90-150200.4.14.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'netty-poms-4.1.90-150200.4.14.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'netty-poms-4.1.90-150200.4.14.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'netty-tcnative-2.0.59-150200.3.10.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'netty-tcnative-2.0.59-150200.3.10.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'netty-4.1.90-150200.4.14.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'netty-javadoc-4.1.90-150200.4.14.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'netty-poms-4.1.90-150200.4.14.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'netty-tcnative-2.0.59-150200.3.10.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'netty-tcnative-javadoc-2.0.59-150200.3.10.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'netty / netty-javadoc / netty-poms / netty-tcnative / etc');
}
