#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2228-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(176044);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id(
    "CVE-2022-43552",
    "CVE-2023-23916",
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27538",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2228-1");
  script_xref(name:"IAVA", value:"2023-A-0008-S");
  script_xref(name:"IAVA", value:"2023-A-0259");
  script_xref(name:"IAVA", value:"2023-A-0153-S");

  script_name(english:"SUSE SLES12 Security Update : curl (SUSE-SU-2023:2228-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2023:2228-1 advisory.

  - A use after free vulnerability exists in curl <7.87.0. Curl can be asked to *tunnel* virtually all
    protocols it supports through an HTTP proxy. HTTP proxies can (and often do) deny such tunnel operations.
    When getting denied to tunnel the specific protocols SMB or TELNET, curl would use a heap-allocated struct
    after it had been freed, in its transfer shutdown code path. (CVE-2022-43552)

  - An allocation of resources without limits or throttling vulnerability exists in curl <v7.88.0 based on the
    chained HTTP compression algorithms, meaning that a server response can be compressed multiple times and
    potentially with differentalgorithms. The number of acceptable links in this decompression chain
    wascapped, but the cap was implemented on a per-header basis allowing a maliciousserver to insert a
    virtually unlimited number of compression steps simply byusing many headers. The use of such a
    decompression chain could result in a malloc bomb, making curl end up spending enormous amounts of
    allocated heap memory, or trying to and returning out of memory errors. (CVE-2023-23916)

  - A vulnerability in input validation exists in curl <8.0 during communication using the TELNET protocol may
    allow an attacker to pass on maliciously crafted user name and telnet options during server negotiation.
    The lack of proper input scrubbing allows an attacker to send content or perform option negotiation
    without the application's intent. This vulnerability could be exploited if an application allows user
    input, thereby enabling attackers to execute arbitrary code on the system. (CVE-2023-27533)

  - A path traversal vulnerability exists in curl <8.0.0 SFTP implementation causes the tilde (~) character to
    be wrongly replaced when used as a prefix in the first path element, in addition to its intended use as
    the first element to indicate a path relative to the user's home directory. Attackers can exploit this
    flaw to bypass filtering or execute arbitrary code by crafting a path like /~2/foo while accessing a
    server with a specific user. (CVE-2023-27534)

  - An authentication bypass vulnerability exists in libcurl <8.0.0 in the FTP connection reuse feature that
    can result in wrong credentials being used during subsequent transfers. Previously created connections are
    kept in a connection pool for reuse if they match the current setup. However, certain FTP settings such as
    CURLOPT_FTP_ACCOUNT, CURLOPT_FTP_ALTERNATIVE_TO_USER, CURLOPT_FTP_SSL_CCC, and CURLOPT_USE_SSL were not
    included in the configuration match checks, causing them to match too easily. This could lead to libcurl
    using the wrong credentials when performing a transfer, potentially allowing unauthorized access to
    sensitive information. (CVE-2023-27535)

  - An authentication bypass vulnerability exists libcurl <8.0.0 in the connection reuse feature which can
    reuse previously established connections with incorrect user permissions due to a failure to check for
    changes in the CURLOPT_GSSAPI_DELEGATION option. This vulnerability affects krb5/kerberos/negotiate/GSSAPI
    transfers and could potentially result in unauthorized access to sensitive information. The safest option
    is to not reuse connections if the CURLOPT_GSSAPI_DELEGATION option has been changed. (CVE-2023-27536)

  - An authentication bypass vulnerability exists in libcurl prior to v8.0.0 where it reuses a previously
    established SSH connection despite the fact that an SSH option was modified, which should have prevented
    reuse. libcurl maintains a pool of previously used connections to reuse them for subsequent transfers if
    the configurations match. However, two SSH settings were omitted from the configuration check, allowing
    them to match easily, potentially leading to the reuse of an inappropriate connection. (CVE-2023-27538)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211339");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-May/029437.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-43552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-27533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-27534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-27535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-27536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-27538");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28322");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl, libcurl4 and / or libcurl4-32bit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27533");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-27534");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcurl4-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'curl-7.60.0-4.56.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4', 'sles-release-4']},
    {'reference':'libcurl4-32bit-7.60.0-4.56.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4', 'sles-release-4']},
    {'reference':'libcurl4-7.60.0-4.56.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4', 'sles-release-4']},
    {'reference':'curl-7.60.0-4.56.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libcurl4-32bit-7.60.0-4.56.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libcurl4-7.60.0-4.56.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'curl-7.60.0-4.56.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'libcurl4-7.60.0-4.56.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-4']}
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
      severity   : SECURITY_HOLE,
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
