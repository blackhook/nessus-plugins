#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2760-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177917);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/04");

  script_cve_id("CVE-2016-7069", "CVE-2017-7557", "CVE-2018-14663");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2760-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : dnsdist (SUSE-SU-2023:2760-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:2760-1 advisory.

  - An issue has been found in dnsdist before 1.2.0 in the way EDNS0 OPT records are handled when parsing
    responses from a backend. When dnsdist is configured to add EDNS Client Subnet to a query, the response
    may contain an EDNS0 OPT record that has to be removed before forwarding the response to the initial
    client. On a 32-bit system, the pointer arithmetic used when parsing the received response to remove that
    record might trigger an undefined behavior leading to a crash. (CVE-2016-7069)

  - dnsdist version 1.1.0 is vulnerable to a flaw in authentication mechanism for REST API potentially
    allowing CSRF attack. (CVE-2017-7557)

  - An issue has been found in PowerDNS DNSDist before 1.3.3 allowing a remote attacker to craft a DNS query
    with trailing data such that the addition of a record by dnsdist, for example an OPT record when adding
    EDNS Client Subnet, might result in the trailing data being smuggled to the backend as a valid record
    while not seen by dnsdist. This is an issue when dnsdist is deployed as a DNS Firewall and used to filter
    some records that should not be received by the backend. This issue occurs only when either the
    'useClientSubnet' or the experimental 'addXPF' parameters are used when declaring a new backend.
    (CVE-2018-14663)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1054799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1054802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114511");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-July/030176.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7557");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14663");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7557");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dnsdist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libluajit-5_1-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:luajit");
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
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'dnsdist-1.8.0-150400.9.3.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'dnsdist-1.8.0-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'dnsdist-1.8.0-150400.9.3.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'dnsdist-1.8.0-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'luajit-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'luajit-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'5', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'luajit-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'luajit-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libluajit-5_1-2-32bit-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'luajit-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'luajit-devel-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libluajit-5_1-2-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libluajit-5_1-2-32bit-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'luajit-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'luajit-devel-2.1.0~beta3+git.1624618403.e9577376-150400.4.2.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dnsdist / libluajit-5_1-2 / libluajit-5_1-2-32bit / luajit / etc');
}
