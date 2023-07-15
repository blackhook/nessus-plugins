#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:6306. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164631);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2021-46659",
    "CVE-2021-46661",
    "CVE-2021-46663",
    "CVE-2021-46664",
    "CVE-2021-46665",
    "CVE-2021-46668",
    "CVE-2021-46669",
    "CVE-2022-21427",
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
    "CVE-2022-27383",
    "CVE-2022-27384",
    "CVE-2022-27386",
    "CVE-2022-27387",
    "CVE-2022-27445",
    "CVE-2022-27447",
    "CVE-2022-27448",
    "CVE-2022-27449",
    "CVE-2022-27452",
    "CVE-2022-27456",
    "CVE-2022-27458",
    "CVE-2022-31622",
    "CVE-2022-31623",
    "CVE-2022-32083",
    "CVE-2022-32085",
    "CVE-2022-32087",
    "CVE-2022-32088"
  );
  script_xref(name:"RHSA", value:"2022:6306");

  script_name(english:"RHEL 7 : rh-mariadb103-galera and rh-mariadb103-mariadb (RHSA-2022:6306)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:6306 advisory.

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

  - mysql: Server: FTS unspecified vulnerability (CPU Apr 2022) (CVE-2022-21427)

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

  - mariadb: use-after-poison in my_strcasecmp_8bit() of ctype-simple.c (CVE-2022-27383)

  - mariadb: crash via component Item_subselect::init_expr_cache_tracker (CVE-2022-27384)

  - mariadb: server crashes in query_arena::set_query_arena upon SELECT from view (CVE-2022-27386)

  - mariadb: assertion failures in decimal_bin_size (CVE-2022-27387)

  - mariadb: assertion failure in compare_order_elements (CVE-2022-27445)

  - mariadb: use-after-poison in Binary_string::free_buffer (CVE-2022-27447, CVE-2022-27458)

  - mariadb: crash in multi-update and implicit grouping (CVE-2022-27448)

  - mariadb: assertion failure in sql/item_func.cc (CVE-2022-27449)

  - mariadb: assertion failure in sql/item_cmpfunc.cc (CVE-2022-27452)

  - mariadb: assertion failure in VDec::VDec at /sql/sql_type.cc (CVE-2022-27456)

  - mariadb: improper locking due to the unreleased lock in extra/mariabackup/ds_compress.cc (CVE-2022-31622,
    CVE-2022-31623)

  - mariadb: server crash at Item_subselect::init_expr_cache_tracker (CVE-2022-32083)

  - mariadb: server crash in Item_func_in::cleanup/Item::cleanup_processor (CVE-2022-32085)

  - mariadb: server crash in Item_args::walk_args (CVE-2022-32087)

  - mariadb: segmentation fault in Exec_time_tracker::get_loops/Filesort_tracker::report_use/filesort
    (CVE-2022-32088)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46661");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46663");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46664");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46665");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46668");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46669");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21427");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21595");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24048");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24050");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24051");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24052");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27376");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27377");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27378");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27379");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27380");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27381");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27383");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27384");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27386");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27387");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27445");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27447");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27449");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27452");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27456");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27458");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-31622");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-31623");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-32083");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-32085");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-32087");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-32088");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:6306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2049302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2068211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2068233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2068234");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2069833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2075005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2075006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2075691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2075693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2075694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2075695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2075697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2075700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2076145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2092354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2092360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2104425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2104431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2104434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2106008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142862");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24052");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 89, 119, 120, 122, 229, 400, 404, 416, 476, 617, 667, 1173);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-backup-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-config-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-connect-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-server-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-server-galera-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-server-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-server-utils-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-mariadb-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/debug',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/os',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/os',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-mariadb103-mariadb-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-syspaths-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-syspaths-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-syspaths-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-common-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-common-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-common-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-syspaths-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-syspaths-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-syspaths-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-connect-engine-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-connect-engine-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-connect-engine-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-devel-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-devel-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-devel-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-errmsg-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-errmsg-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-errmsg-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-gssapi-server-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-gssapi-server-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-gssapi-server-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-oqgraph-engine-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-oqgraph-engine-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-oqgraph-engine-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-syspaths-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-syspaths-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-syspaths-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-syspaths-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-syspaths-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-syspaths-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-syspaths-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-syspaths-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-syspaths-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-syspaths-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-syspaths-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-syspaths-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-test-10.3.35-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-test-10.3.35-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-test-10.3.35-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-mariadb103-mariadb / rh-mariadb103-mariadb-backup / etc');
}
