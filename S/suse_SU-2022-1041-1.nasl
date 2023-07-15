#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1041-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159349);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2019-6502",
    "CVE-2019-15945",
    "CVE-2019-15946",
    "CVE-2019-19479",
    "CVE-2019-19481",
    "CVE-2019-20792",
    "CVE-2020-26570",
    "CVE-2020-26571",
    "CVE-2020-26572",
    "CVE-2021-42779",
    "CVE-2021-42780",
    "CVE-2021-42781",
    "CVE-2021-42782"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1041-1");

  script_name(english:"SUSE SLES15 Security Update : opensc (SUSE-SU-2022:1041-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:1041-1 advisory.

  - OpenSC before 0.20.0-rc1 has an out-of-bounds access of an ASN.1 Bitstring in decode_bit_string in
    libopensc/asn1.c. (CVE-2019-15945)

  - OpenSC before 0.20.0-rc1 has an out-of-bounds access of an ASN.1 Octet string in asn1_decode_entry in
    libopensc/asn1.c. (CVE-2019-15946)

  - An issue was discovered in OpenSC through 0.19.0 and 0.20.x through 0.20.0-rc3. libopensc/card-setcos.c
    has an incorrect read operation during parsing of a SETCOS file attribute. (CVE-2019-19479)

  - An issue was discovered in OpenSC through 0.19.0 and 0.20.x through 0.20.0-rc3. libopensc/card-cac1.c
    mishandles buffer limits for CAC certificates. (CVE-2019-19481)

  - OpenSC before 0.20.0 has a double free in coolkey_free_private_data because coolkey_add_object in
    libopensc/card-coolkey.c lacks a uniqueness check. (CVE-2019-20792)

  - sc_context_create in ctx.c in libopensc in OpenSC 0.19.0 has a memory leak, as demonstrated by a call from
    eidenv. (CVE-2019-6502)

  - The Oberthur smart card software driver in OpenSC before 0.21.0-rc1 has a heap-based buffer overflow in
    sc_oberthur_read_file. (CVE-2020-26570)

  - The gemsafe GPK smart card software driver in OpenSC before 0.21.0-rc1 has a stack-based buffer overflow
    in sc_pkcs15emu_gemsafeGPK_init. (CVE-2020-26571)

  - The TCOS smart card software driver in OpenSC before 0.21.0-rc1 has a stack-based buffer overflow in
    tcos_decipher. (CVE-2020-26572)

  - A heap use after free issue was found in Opensc before version 0.22.0 in sc_file_valid. (CVE-2021-42779)

  - A use after return issue was found in Opensc before version 0.22.0 in insert_pin function that could
    potentially crash programs using the library. (CVE-2021-42780)

  - Heap buffer overflow issues were found in Opensc before version 0.22.0 in pkcs15-oberthur.c that could
    potentially crash programs using the library. (CVE-2021-42781)

  - Stack buffer overflow issues were found in Opensc before version 0.22.0 in various places that could
    potentially crash programs using the library. (CVE-2021-42782)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1122756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1170809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192005");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010580.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2f28079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-6502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42782");
  script_set_attribute(attribute:"solution", value:
"Update the affected opensc package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20792");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:opensc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'opensc-0.18.0-150000.3.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'opensc-0.18.0-150000.3.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'opensc-0.18.0-150000.3.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'opensc-0.18.0-150000.3.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'opensc-0.18.0-150000.3.23.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'opensc');
}
