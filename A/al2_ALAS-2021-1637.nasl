#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1637.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149864);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/24");

  script_cve_id("CVE-2018-10932");
  script_xref(name:"ALAS", value:"2021-1637");

  script_name(english:"Amazon Linux 2 : lldpad (ALAS-2021-1637)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of lldpad installed on the remote host is prior to 1.0.1-5.git036e314. It is, therefore, affected by a
vulnerability as referenced in the ALAS2-2021-1637 advisory.

  - lldptool version 1.0.1 and older can print a raw, unsanitized attacker controlled buffer when mngAddr
    information is displayed. This may allow an attacker to inject shell control characters into the buffer
    and impact the behavior of the terminal. (CVE-2018-10932)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1637.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-10932");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update lldpad' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lldpad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lldpad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lldpad-devel");
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
    {'reference':'lldpad-1.0.1-5.git036e314.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldpad-1.0.1-5.git036e314.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldpad-1.0.1-5.git036e314.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldpad-debuginfo-1.0.1-5.git036e314.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldpad-debuginfo-1.0.1-5.git036e314.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldpad-debuginfo-1.0.1-5.git036e314.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldpad-devel-1.0.1-5.git036e314.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldpad-devel-1.0.1-5.git036e314.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldpad-devel-1.0.1-5.git036e314.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lldpad / lldpad-debuginfo / lldpad-devel");
}