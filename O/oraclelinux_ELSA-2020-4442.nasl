##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4442.
##

include('compat.inc');

if (description)
{
  script_id(142752);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/13");

  script_cve_id(
    "CVE-2019-5018",
    "CVE-2019-16168",
    "CVE-2019-20218",
    "CVE-2020-6405",
    "CVE-2020-9327",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632"
  );
  script_bugtraq_id(108294);

  script_name(english:"Oracle Linux 8 : sqlite (ELSA-2020-4442)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4442 advisory.

  - An exploitable use after free vulnerability exists in the window function functionality of Sqlite3 3.26.0.
    A specially crafted SQL command can cause a use after free vulnerability, potentially resulting in remote
    code execution. An attacker can send a malicious SQL command to trigger this vulnerability.
    (CVE-2019-5018)

  - Out of bounds read in SQLite in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (CVE-2020-6405)

  - In SQLite 3.31.1, isAuxiliaryVtabOperator allows attackers to trigger a NULL pointer dereference and
    segmentation fault because of generated column optimizations. (CVE-2020-9327)

  - SQLite before 3.32.0 allows a virtual table to be renamed to the name of one of its shadow tables, related
    to alter.c and build.c. (CVE-2020-13631)

  - In SQLite through 3.29.0, whereLoopAddBtreeIndex in sqlite3.c can crash a browser or other application
    because of missing validation of a sqlite_stat1 sz field, aka a severe division by zero in the query
    planner. (CVE-2019-16168)

  - selectExpander in select.c in SQLite 3.30.1 proceeds with WITH stack unwinding even after a parsing error.
    (CVE-2019-20218)

  - ext/fts3/fts3.c in SQLite before 3.32.0 has a use-after-free in fts3EvalNextRow, related to the snippet
    feature. (CVE-2020-13630)

  - ext/fts3/fts3_snippet.c in SQLite before 3.32.0 has a NULL pointer dereference via a crafted matchinfo()
    query. (CVE-2020-13632)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4442.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sqlite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sqlite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sqlite-libs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'lemon-3.26.0-11.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'lemon-3.26.0-11.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'sqlite-3.26.0-11.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'sqlite-3.26.0-11.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'sqlite-3.26.0-11.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'sqlite-devel-3.26.0-11.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'sqlite-devel-3.26.0-11.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'sqlite-devel-3.26.0-11.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'sqlite-doc-3.26.0-11.el8', 'release':'8'},
    {'reference':'sqlite-libs-3.26.0-11.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'sqlite-libs-3.26.0-11.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'sqlite-libs-3.26.0-11.el8', 'cpu':'x86_64', 'release':'8'}
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
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lemon / sqlite / sqlite-devel / etc');
}