##
# (C) Tenable, Inc.
##
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(161758);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_cve_id("CVE-2022-24903");
  script_xref(name:"RHSA", value:"RHSA-2022:4803");

  script_name(english:"Scientific Linux Security Update : rsyslog on SL7.x x86_64 (2022:4803)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Scientific Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
SLSA-2022:4803-1 advisory.

  - rsyslog: Heap-based overflow in TCP syslog server (CVE-2022-24903)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.scientificlinux.org/category/sl-errata/slsa-20224803-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-libdbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmkubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmsnmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-udpspoof");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Scientific Linux' >!< release) audit(AUDIT_OS_NOT, 'Scientific Linux');
var os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Scientific Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Scientific Linux 7.x', 'Scientific Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Scientific Linux', cpu);

var pkgs = [
    {'reference':'rsyslog-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-crypto-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-debuginfo-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-doc-8.24.0-57.el7_9.3', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-elasticsearch-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gnutls-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gssapi-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-kafka-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-libdbi-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmaudit-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmjsonparse-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmkubernetes-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmnormalize-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmsnmptrapd-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mysql-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-pgsql-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-relp-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-snmp-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-udpspoof-8.24.0-57.el7_9.3', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rsyslog / rsyslog-crypto / rsyslog-debuginfo / etc');
}
