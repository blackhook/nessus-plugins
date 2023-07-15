#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1647.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150993);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/30");

  script_cve_id(
    "CVE-2018-15686",
    "CVE-2018-16864",
    "CVE-2018-16866",
    "CVE-2019-3815",
    "CVE-2019-20386"
  );
  script_xref(name:"ALAS", value:"2021-1647");

  script_name(english:"Amazon Linux 2 : systemd (ALAS-2021-1647)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of systemd installed on the remote host is prior to 219-78. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1647 advisory.

  - A vulnerability in unit_deserialize of systemd allows an attacker to supply arbitrary state across systemd
    re-execution via NotifyAccess. This can be used to improperly influence systemd execution and possibly
    lead to root privilege escalation. Affected releases are systemd versions up to and including 239.
    (CVE-2018-15686)

  - An allocation of memory without limits, that could result in the stack clashing with another memory
    region, was discovered in systemd-journald when a program with long command line arguments calls syslog. A
    local attacker may use this flaw to crash systemd-journald or escalate his privileges. Versions through
    v240 are vulnerable. (CVE-2018-16864)

  - An out of bounds read was discovered in systemd-journald in the way it parses log messages that terminate
    with a colon ':'. A local attacker can use this flaw to disclose process memory data. Versions from v221
    to v239 are vulnerable. (CVE-2018-16866)

  - An issue was discovered in button_open in login/logind-button.c in systemd before 243. When executing the
    udevadm trigger command, a memory leak may occur. (CVE-2019-20386)

  - A memory leak was discovered in the backport of fixes for CVE-2018-16864 in Red Hat Enterprise Linux.
    Function dispatch_message_real() in journald-server.c does not free the memory allocated by
    set_iovec_field_free() to store the `_CMDLINE=` entry. A local attacker may use this flaw to make systemd-
    journald crash. This issue only affects versions shipped with Red Hat Enterprise since v219-62.2.
    (CVE-2019-3815)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1647.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-15686");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16866");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20386");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3815");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update systemd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15686");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'libgudev1-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debuginfo-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debuginfo-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debuginfo-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-78.amzn2.0.14', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-78.amzn2.0.14', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-78.amzn2.0.14', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgudev1 / libgudev1-devel / systemd / etc");
}