##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2022-1594.
##

include('compat.inc');

if (description)
{
  script_id(161998);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2014-3634", "CVE-2022-24903");

  script_name(english:"Amazon Linux AMI : rsyslog (ALAS-2022-1594)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of rsyslog installed on the remote host is prior to 5.8.10-9.29. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2022-1594 advisory.

  - rsyslog before 7.6.6 and 8.x before 8.4.1 and sysklogd 1.5 and earlier allows remote attackers to cause a
    denial of service (crash), possibly execute arbitrary code, or have other unspecified impact via a crafted
    priority (PRI) value that triggers an out-of-bounds array access. (CVE-2014-3634)

  - Rsyslog is a rocket-fast system for log processing. Modules for TCP syslog reception have a potential heap
    buffer overflow when octet-counted framing is used. This can result in a segfault or some other
    malfunction. As of our understanding, this vulnerability can not be used for remote code execution. But
    there may still be a slight chance for experts to do that. The bug occurs when the octet count is read.
    While there is a check for the maximum number of octets, digits are written to a heap buffer even when the
    octet count is over the maximum, This can be used to overrun the memory buffer. However, once the sequence
    of digits stop, no additional characters can be added to the buffer. In our opinion, this makes remote
    exploits impossible or at least highly complex. Octet-counted framing is one of two potential framing
    modes. It is relatively uncommon, but enabled by default on receivers. Modules `imtcp`, `imptcp`,
    `imgssapi`, and `imhttp` are used for regular syslog message reception. It is best practice not to
    directly expose them to the public. When this practice is followed, the risk is considerably lower. Module
    `imdiag` is a diagnostics module primarily intended for testbench runs. We do not expect it to be present
    on any production installation. Octet-counted framing is not very common. Usually, it needs to be
    specifically enabled at senders. If users do not need it, they can turn it off for the most important
    modules. This will mitigate the vulnerability. (CVE-2022-24903)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2022-1594.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2014-3634.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24903.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update rsyslog' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3634");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'rsyslog-5.8.10-9.29.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-5.8.10-9.29.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-debuginfo-5.8.10-9.29.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-debuginfo-5.8.10-9.29.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gnutls-5.8.10-9.29.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gnutls-5.8.10-9.29.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gssapi-5.8.10-9.29.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-gssapi-5.8.10-9.29.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mysql-5.8.10-9.29.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-mysql-5.8.10-9.29.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-pgsql-5.8.10-9.29.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-pgsql-5.8.10-9.29.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-snmp-5.8.10-9.29.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rsyslog-snmp-5.8.10-9.29.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-debuginfo / rsyslog-gnutls / etc");
}