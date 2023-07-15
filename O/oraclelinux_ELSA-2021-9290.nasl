#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9290.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150722);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2019-10129",
    "CVE-2019-10130",
    "CVE-2019-10164",
    "CVE-2019-10208",
    "CVE-2020-1720",
    "CVE-2020-14349",
    "CVE-2020-14350",
    "CVE-2020-25694",
    "CVE-2020-25695",
    "CVE-2020-25696"
  );
  script_xref(name:"IAVB", value:"2019-B-0040-S");
  script_xref(name:"IAVB", value:"2019-B-0050-S");
  script_xref(name:"IAVB", value:"2019-B-0072-S");
  script_xref(name:"IAVB", value:"2020-B-0015-S");
  script_xref(name:"IAVB", value:"2020-B-0047-S");
  script_xref(name:"IAVB", value:"2020-B-0069-S");

  script_name(english:"Oracle Linux 7 : rh-postgresql10-postgresql (ELSA-2021-9290)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-9290 advisory.

  - A vulnerability was found in PostgreSQL versions 11.x up to excluding 11.3, 10.x up to excluding 10.8,
    9.6.x up to, excluding 9.6.13, 9.5.x up to, excluding 9.5.17. PostgreSQL maintains column statistics for
    tables. Certain statistics, such as histograms and lists of most common values, contain values taken from
    the column. PostgreSQL does not evaluate row security policies before consulting those statistics during
    query planning; an attacker can exploit this to read the most common values of certain columns. Affected
    columns are those for which the attacker has SELECT privilege and for which, in an ordinary query, row-
    level security prunes the set of rows visible to the attacker. (CVE-2019-10130)

  - A flaw was discovered in postgresql versions 9.4.x before 9.4.24, 9.5.x before 9.5.19, 9.6.x before
    9.6.15, 10.x before 10.10 and 11.x before 11.5 where arbitrary SQL statements can be executed given a
    suitable SECURITY DEFINER function. An attacker, with EXECUTE permission on the function, can execute
    arbitrary SQL as the owner of the function. (CVE-2019-10208)

  - It was found that PostgreSQL versions before 12.4, before 11.9 and before 10.14 did not properly sanitize
    the search_path during logical replication. An authenticated attacker could use this flaw in an attack
    similar to CVE-2018-1058, in order to execute arbitrary SQL command in the context of the user used for
    replication. (CVE-2020-14349)

  - PostgreSQL versions 10.x before 10.9 and versions 11.x before 11.4 are vulnerable to a stack-based buffer
    overflow. Any authenticated user can overflow a stack-based buffer by changing the user's own password to
    a purpose-crafted value. This often suffices to execute arbitrary code as the PostgreSQL operating system
    account. (CVE-2019-10164)

  - A flaw was found in PostgreSQL's ALTER ... DEPENDS ON EXTENSION, where sub-commands did not perform
    authorization checks. An authenticated attacker could use this flaw in certain configurations to perform
    drop objects such as function, triggers, et al., leading to database corruption. This issue affects
    PostgreSQL versions before 12.2, before 11.7, before 10.12 and before 9.6.17. (CVE-2020-1720)

  - It was found that some PostgreSQL extensions did not use search_path safely in their installation script.
    An attacker with sufficient privileges could use this flaw to trick an administrator into executing a
    specially crafted script, during the installation or update of such extension. This affects PostgreSQL
    versions before 12.4, before 11.9, before 10.14, before 9.6.19, and before 9.5.23. (CVE-2020-14350)

  - A flaw was found in PostgreSQL versions before 13.1, before 12.5, before 11.10, before 10.15, before
    9.6.20 and before 9.5.24. If a client application that creates additional database connections only reuses
    the basic connection parameters while dropping security-relevant parameters, an opportunity for a man-in-
    the-middle attack, or the ability to observe clear-text transmissions, could exist. The highest threat
    from this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2020-25694)

  - A flaw was found in the psql interactive terminal of PostgreSQL in versions before 13.1, before 12.5,
    before 11.10, before 10.15, before 9.6.20 and before 9.5.24. If an interactive psql session uses \gset
    when querying a compromised server, the attacker can execute arbitrary code as the operating system
    account running psql. The highest threat from this vulnerability is to data confidentiality and integrity
    as well as system availability. (CVE-2020-25696)

  - A flaw was found in PostgreSQL versions before 13.1, before 12.5, before 11.10, before 10.15, before
    9.6.20 and before 9.5.24. An attacker having permission to create non-temporary objects in at least one
    schema can execute arbitrary SQL functions under the identity of a superuser. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-25695)

  - A vulnerability was found in postgresql versions 11.x prior to 11.3. Using a purpose-crafted insert to a
    partitioned table, an attacker can read arbitrary bytes of server memory. In the default configuration,
    any user can create a partitioned table suitable for this attack. (Exploit prerequisites are the same as
    for CVE-2018-1052). (CVE-2019-10129)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9290.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10164");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-contrib-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-server-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql10-postgresql-test");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

pkgs = [
    {'reference':'rh-postgresql10-postgresql-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-contrib-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-contrib-syspaths-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-devel-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-docs-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-libs-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-plperl-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-plpython-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-pltcl-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-server-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-server-syspaths-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-static-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-syspaths-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rh-postgresql10-postgresql-test-10.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-postgresql10-postgresql / rh-postgresql10-postgresql-contrib / rh-postgresql10-postgresql-contrib-syspaths / etc');
}
