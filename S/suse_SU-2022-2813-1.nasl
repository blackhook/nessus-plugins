##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2813-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(164224);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2022-27781",
    "CVE-2022-27782",
    "CVE-2022-32206",
    "CVE-2022-32208"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2813-1");
  script_xref(name:"IAVA", value:"2022-A-0224-S");
  script_xref(name:"IAVA", value:"2022-A-0255-S");

  script_name(english:"SUSE SLES12 Security Update : curl (SUSE-SU-2022:2813-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:2813-1 advisory.

  - libcurl provides the `CURLOPT_CERTINFO` option to allow applications torequest details to be returned
    about a server's certificate chain.Due to an erroneous function, a malicious server could make libcurl
    built withNSS get stuck in a never-ending busy-loop when trying to retrieve thatinformation.
    (CVE-2022-27781)

  - libcurl would reuse a previously created connection even when a TLS or SSHrelated option had been changed
    that should have prohibited reuse.libcurl keeps previously used connections in a connection pool for
    subsequenttransfers to reuse if one of them matches the setup. However, several TLS andSSH settings were
    left out from the configuration match checks, making themmatch too easily. (CVE-2022-27782)

  - curl < 7.84.0 supports chained HTTP compression algorithms, meaning that a serverresponse can be
    compressed multiple times and potentially with different algorithms. The number of acceptable links in
    this decompression chain was unbounded, allowing a malicious server to insert a virtually unlimited
    number of compression steps.The use of such a decompression chain could result in a malloc bomb,
    makingcurl end up spending enormous amounts of allocated heap memory, or trying toand returning out of
    memory errors. (CVE-2022-32206)

  - When curl < 7.84.0 does FTP transfers secured by krb5, it handles message verification failures wrongly.
    This flaw makes it possible for a Man-In-The-Middle attack to go unnoticed and even allows it to inject
    data to the client. (CVE-2022-32208)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200737");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-August/011916.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbee93a4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32208");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl, libcurl4 and / or libcurl4-32bit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcurl4-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'curl-7.60.0-4.38.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libcurl4-32bit-7.60.0-4.38.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libcurl4-7.60.0-4.38.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'curl-7.60.0-4.38.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libcurl4-32bit-7.60.0-4.38.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libcurl4-7.60.0-4.38.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl4 / libcurl4-32bit');
}
