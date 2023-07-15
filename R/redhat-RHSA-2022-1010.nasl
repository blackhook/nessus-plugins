#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1010. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159167);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2021-2154",
    "CVE-2021-2166",
    "CVE-2021-2372",
    "CVE-2021-2389",
    "CVE-2021-35604",
    "CVE-2021-46657",
    "CVE-2021-46662",
    "CVE-2021-46666",
    "CVE-2021-46667"
  );
  script_xref(name:"RHSA", value:"2022:1010");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0333");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : rh-mariadb103-mariadb (RHSA-2022:1010)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:1010 advisory.

  - mysql: Server: DML unspecified vulnerability (CPU Apr 2021) (CVE-2021-2154, CVE-2021-2166)

  - mysql: InnoDB unspecified vulnerability (CPU Jul 2021) (CVE-2021-2372, CVE-2021-2389)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2021) (CVE-2021-35604)

  - mariadb: Crash in get_sort_by_table() in subquery with ORDER BY having outer ref (CVE-2021-46657)

  - mariadb: save_window_function_values triggers an abort during IN subquery (CVE-2021-46658)

  - mariadb: Crash in set_var.cc via certain UPDATE queries with nested subqueries (CVE-2021-46662)

  - mariadb: Crash caused by mishandling of a pushdown from a HAVING clause to a WHERE clause (CVE-2021-46666)

  - mariadb: Integer overflow in sql_lex.cc integer leading to crash (CVE-2021-46667)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2022) (CVE-2022-21451)

  - mariadb: crash in Used_tables_and_const_cache::used_tables_and_const_cache_join (CVE-2022-27385)

  - mariadb: improper locking due to unreleased lock in the ds_xbstream.cc (CVE-2022-31621)

  - mariadb: DoS due to improper locking due to unreleased lock in plugin/server_audit/server_audit.c
    (CVE-2022-31624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2154");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2166");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2372");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2389");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35604");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46657");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46658");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46662");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-46667");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21451");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27385");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-31621");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-31624");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2049294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2049305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2075001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2092353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2092362");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 89, 190, 404, 667);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb103-galera");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
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
      {'reference':'rh-mariadb103-galera-25.3.34-4.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mariadb103-galera-25.3.34-4.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mariadb103-galera-25.3.34-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mariadb103-mariadb-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-syspaths-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-syspaths-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-backup-syspaths-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-common-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-common-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-common-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-syspaths-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-syspaths-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-config-syspaths-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-connect-engine-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-connect-engine-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-connect-engine-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-devel-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-devel-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-devel-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-errmsg-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-errmsg-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-errmsg-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-gssapi-server-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-gssapi-server-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-gssapi-server-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-oqgraph-engine-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-oqgraph-engine-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-oqgraph-engine-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-syspaths-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-syspaths-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-galera-syspaths-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-syspaths-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-syspaths-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-syspaths-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-syspaths-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-syspaths-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-server-utils-syspaths-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-syspaths-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-syspaths-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-syspaths-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-test-10.3.32-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-test-10.3.32-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb103-mariadb-test-10.3.32-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-mariadb103-galera / rh-mariadb103-mariadb / etc');
}
