##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-56191.
##

include('compat.inc');

if (description)
{
  script_id(144565);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2019-10130",
    "CVE-2019-10208",
    "CVE-2020-1720",
    "CVE-2020-14350",
    "CVE-2020-25694",
    "CVE-2020-25695",
    "CVE-2020-25696"
  );
  script_bugtraq_id(108452);
  script_xref(name:"IAVB", value:"2020-B-0069-S");

  script_name(english:"Oracle Linux 8 : ELSA-2020-5619-1: / postgresql:9.6 (ELSA-2020-56191)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-56191 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5619-1.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plpython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-test-rpm-macros");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

pkgs = [
    {'reference':'postgresql-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-contrib-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-docs-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-plperl-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-plpython3-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-pltcl-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-server-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-server-devel-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-static-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-test-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'},
    {'reference':'postgresql-test-rpm-macros-9.6.20-1.module+el8.3.0+9604+f0f52296', 'release':'8'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'postgresql / postgresql-contrib / postgresql-docs / etc');
}
