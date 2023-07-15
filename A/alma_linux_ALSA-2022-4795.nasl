#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:4795.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167703);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/17");

  script_cve_id("CVE-2022-24903");
  script_xref(name:"ALSA", value:"2022:4795");

  script_name(english:"AlmaLinux 9 : rsyslog (ALSA-2022:4795)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2022:4795 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2022-4795.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-logrotate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-mmaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-mmfields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-mmkubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-mmsnmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-omamqp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rsyslog-udpspoof");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'rsyslog-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-crypto-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-crypto-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-doc-8.2102.0-101.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-elasticsearch-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-elasticsearch-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gnutls-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gnutls-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gssapi-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gssapi-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-kafka-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-kafka-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-logrotate-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-logrotate-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmaudit-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmaudit-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmfields-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmfields-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmjsonparse-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmjsonparse-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmkubernetes-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmkubernetes-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmnormalize-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmnormalize-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmsnmptrapd-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mmsnmptrapd-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mysql-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mysql-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-omamqp1-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-omamqp1-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-openssl-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-openssl-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-pgsql-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-pgsql-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-relp-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-relp-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-snmp-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-snmp-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-udpspoof-8.2102.0-101.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-udpspoof-8.2102.0-101.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rsyslog / rsyslog-crypto / rsyslog-doc / rsyslog-elasticsearch / etc');
}
