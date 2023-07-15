##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2022:5826. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163712);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2021-46659",
    "CVE-2021-46661",
    "CVE-2021-46663",
    "CVE-2021-46664",
    "CVE-2021-46665",
    "CVE-2021-46668",
    "CVE-2021-46669",
    "CVE-2022-24048",
    "CVE-2022-24050",
    "CVE-2022-24051",
    "CVE-2022-24052",
    "CVE-2022-27376",
    "CVE-2022-27377",
    "CVE-2022-27378",
    "CVE-2022-27379",
    "CVE-2022-27380",
    "CVE-2022-27381",
    "CVE-2022-27382",
    "CVE-2022-27383",
    "CVE-2022-27384",
    "CVE-2022-27386",
    "CVE-2022-27387",
    "CVE-2022-27444",
    "CVE-2022-27445",
    "CVE-2022-27446",
    "CVE-2022-27447",
    "CVE-2022-27448",
    "CVE-2022-27449",
    "CVE-2022-27451",
    "CVE-2022-27452",
    "CVE-2022-27455",
    "CVE-2022-27456",
    "CVE-2022-27457",
    "CVE-2022-27458",
    "CVE-2022-31622",
    "CVE-2022-31623"
  );
  script_xref(name:"RHSA", value:"2022:5826");

  script_name(english:"CentOS 8 : mariadb:10.5 (CESA-2022:5826)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
CESA-2022:5826 advisory.

  - mariadb: Crash executing query with VIEW, aggregate and subquery (CVE-2021-46659)

  - mariadb: MariaDB allows an application crash in find_field_in_tables and find_order_in_list via an unused
    common table expression (CTE) (CVE-2021-46661)

  - mariadb: MariaDB through 10.5.13 allows a ha_maria::extra application crash via certain SELECT statements
    (CVE-2021-46663)

  - mariadb: MariaDB through 10.5.9 allows an application crash in sub_select_postjoin_aggr for a NULL value
    of aggr (CVE-2021-46664)

  - mariadb: MariaDB through 10.5.9 allows a sql_parse.cc application crash because of incorrect used_tables
    expectations (CVE-2021-46665)

  - mariadb: MariaDB through 10.5.9 allows an application crash via certain long SELECT DISTINCT statements
    (CVE-2021-46668)

  - mariadb: MariaDB through 10.5.9 allows attackers to trigger a convert_const_to_int use-after-free when the
    BIGINT data type is used (CVE-2021-46669)

  - mysql: C API unspecified vulnerability (CPU Oct 2022) (CVE-2022-21595)

  - mariadb: lack of proper validation of the length of user-supplied data prior to copying it to a fixed-
    length stack-based buffer (CVE-2022-24048)

  - mariadb: lack of validating the existence of an object prior to performing operations on the object
    (CVE-2022-24050)

  - mariadb: lack of proper validation of a user-supplied string before using it as a format specifier
    (CVE-2022-24051)

  - mariadb: CONNECT storage engine heap-based buffer overflow (CVE-2022-24052)

  - mariadb: assertion failure in Item_args::walk_arg (CVE-2022-27376)

  - mariadb: use-after-poison when complex conversion is involved in blob (CVE-2022-27377)

  - mariadb: server crash in create_tmp_table::finalize (CVE-2022-27378)

  - mariadb: server crash in component arg_comparator::compare_real_fixed (CVE-2022-27379)

  - mariadb: server crash at my_decimal::operator= (CVE-2022-27380)

  - mariadb: server crash at Field::set_default via specially crafted SQL statements (CVE-2022-27381)

  - mariadb: assertion failure via component Item_field::used_tables/update_depend_map_for_order
    (CVE-2022-27382)

  - mariadb: use-after-poison in my_strcasecmp_8bit() of ctype-simple.c (CVE-2022-27383)

  - mariadb: crash via component Item_subselect::init_expr_cache_tracker (CVE-2022-27384)

  - mariadb: server crashes in query_arena::set_query_arena upon SELECT from view (CVE-2022-27386)

  - mariadb: assertion failures in decimal_bin_size (CVE-2022-27387)

  - mariadb: crash when using HAVING with NOT EXIST predicate in an equality (CVE-2022-27444)

  - mariadb: assertion failure in compare_order_elements (CVE-2022-27445)

  - mariadb: crash when using HAVING with IS NULL predicate in an equality (CVE-2022-27446)

  - mariadb: use-after-poison in Binary_string::free_buffer (CVE-2022-27447, CVE-2022-27458)

  - mariadb: crash in multi-update and implicit grouping (CVE-2022-27448)

  - mariadb: assertion failure in sql/item_func.cc (CVE-2022-27449)

  - mariadb: crash via window function in expression in ORDER BY (CVE-2022-27451)

  - mariadb: assertion failure in sql/item_cmpfunc.cc (CVE-2022-27452)

  - mariadb: use-after-free when WHERE has subquery with an outer reference in HAVING (CVE-2022-27455)

  - mariadb: assertion failure in VDec::VDec at /sql/sql_type.cc (CVE-2022-27456)

  - mariadb: incorrect key in dup value error after long unique (CVE-2022-27457)

  - mariadb: improper locking due to the unreleased lock in extra/mariabackup/ds_compress.cc (CVE-2022-31622,
    CVE-2022-31623)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:5826");
  script_set_attribute(attribute:"solution", value:
"Update the affected Judy package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24052");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:Judy");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/mariadb');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb:10.5');
if ('10.5' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mariadb:' + module_ver);

var appstreams = {
    'mariadb:10.5': [
      {'reference':'Judy-1.0.5-18.module_el8.4.0+697+2baf600e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Judy-1.0.5-18.module_el8.4.0+697+2baf600e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb:10.5');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Judy');
}
