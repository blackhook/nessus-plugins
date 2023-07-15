#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-1556.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160272);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2021-2154",
    "CVE-2021-2166",
    "CVE-2021-2372",
    "CVE-2021-2389",
    "CVE-2021-35604",
    "CVE-2021-46657",
    "CVE-2021-46658",
    "CVE-2021-46662",
    "CVE-2021-46666",
    "CVE-2021-46667"
  );
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0333");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Linux 8 : mariadb:10.3 (ELSA-2022-1556)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-1556 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2166)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2372)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 5.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2389)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 5.7.33 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2154)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.35 and prior and 8.0.26 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of
    MySQL Server accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2021-35604)

  - MariaDB before 10.6.2 allows an application crash because of mishandling of a pushdown from a HAVING
    clause to a WHERE clause. (CVE-2021-46666)

  - MariaDB before 10.6.5 has a sql_lex.cc integer overflow, leading to an application crash. (CVE-2021-46667)

  - get_sort_by_table in MariaDB before 10.6.2 allows an application crash via certain subquery uses of ORDER
    BY. (CVE-2021-46657)

  - save_window_function_values in MariaDB before 10.6.3 allows an application crash because of incorrect
    handling of with_window_func=true for a subquery. (CVE-2021-46658)

  - MariaDB through 10.5.9 allows a set_var.cc application crash via certain uses of an UPDATE statement in
    conjunction with a nested subquery. (CVE-2021-46662)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-1556.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:Judy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-server-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-test");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/mariadb');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb:10.3');
if ('10.3' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mariadb:' + module_ver);

var appstreams = {
    'mariadb:10.3': [
      {'reference':'galera-25.3.34-4.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Judy-1.0.5-18.0.1.module+el8.3.0+9616+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Judy-1.0.5-18.0.1.module+el8.3.0+9616+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Judy-1.0.5-18.0.1.module+el8.3.0+9616+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mariadb-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-backup-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-common-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-devel-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-test-10.3.32-2.0.1.module+el8.5.0+20629+e1b20d6b', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
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
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb:10.3');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Judy / galera / mariadb / etc');
}
