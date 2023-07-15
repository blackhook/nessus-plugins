#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3391-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165484);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2022-32081",
    "CVE-2022-32082",
    "CVE-2022-32083",
    "CVE-2022-32084",
    "CVE-2022-32085",
    "CVE-2022-32086",
    "CVE-2022-32087",
    "CVE-2022-32088",
    "CVE-2022-32089",
    "CVE-2022-32091",
    "CVE-2022-38791"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3391-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : mariadb (SUSE-SU-2022:3391-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3391-1 advisory.

  - MariaDB v10.4 to v10.7 was discovered to contain an use-after-poison in prepare_inplace_add_virtual at
    /storage/innobase/handler/handler0alter.cc. (CVE-2022-32081)

  - MariaDB v10.5 to v10.7 was discovered to contain an assertion failure at table->get_ref_count() == 0 in
    dict0dict.cc. (CVE-2022-32082)

  - MariaDB v10.2 to v10.6.1 was discovered to contain a segmentation fault via the component
    Item_subselect::init_expr_cache_tracker. (CVE-2022-32083)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component sub_select.
    (CVE-2022-32084)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component
    Item_func_in::cleanup/Item::cleanup_processor. (CVE-2022-32085)

  - MariaDB v10.4 to v10.8 was discovered to contain a segmentation fault via the component
    Item_field::fix_outer_field. (CVE-2022-32086)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component
    Item_args::walk_args. (CVE-2022-32087)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component
    Exec_time_tracker::get_loops/Filesort_tracker::report_use/filesort. (CVE-2022-32088)

  - MariaDB v10.5 to v10.7 was discovered to contain a segmentation fault via the component
    st_select_lex_unit::exclude_level. (CVE-2022-32089)

  - MariaDB v10.7 was discovered to contain an use-after-poison in in __interceptor_memset at
    /libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc. (CVE-2022-32091)

  - In MariaDB before 10.9.2, compress_write in extra/mariabackup/ds_compress.cc does not release data_mutex
    upon a stream write failure, which allows local users to trigger a deadlock. (CVE-2022-38791)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202863");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012373.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40463957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32081");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32084");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32091");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38791");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32081");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadbd19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libmariadbd-devel-10.5.17-150300.3.21.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libmariadbd19-10.5.17-150300.3.21.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-10.5.17-150300.3.21.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-client-10.5.17-150300.3.21.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-errormessages-10.5.17-150300.3.21.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-galera-10.5.17-150300.3.21.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-galera-10.5.17-150300.3.21.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-tools-10.5.17-150300.3.21.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libmariadbd-devel-10.5.17-150300.3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libmariadbd19-10.5.17-150300.3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'mariadb-10.5.17-150300.3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'mariadb-bench-10.5.17-150300.3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'mariadb-client-10.5.17-150300.3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'mariadb-errormessages-10.5.17-150300.3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'mariadb-rpm-macros-10.5.17-150300.3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'mariadb-test-10.5.17-150300.3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'mariadb-tools-10.5.17-150300.3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmariadbd-devel / libmariadbd19 / mariadb / mariadb-bench / etc');
}
