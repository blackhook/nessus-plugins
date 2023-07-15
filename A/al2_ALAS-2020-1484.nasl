#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1484.
#

include('compat.inc');

if (description)
{
  script_id(140195);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2019-20907", "CVE-2020-14422");
  script_xref(name:"ALAS", value:"2020-1484");
  script_xref(name:"IAVA", value:"2020-A-0340-S");

  script_name(english:"Amazon Linux 2 : python3 (ALAS-2020-1484)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1484 advisory.

  - In Lib/tarfile.py in Python through 3.8.3, an attacker is able to craft a TAR archive leading to an
    infinite loop when opened by tarfile.open, because _proc_pax lacks header validation. (CVE-2019-20907)

  - Lib/ipaddress.py in Python through 3.8.3 improperly computes hash values in the IPv4Interface and
    IPv6Interface classes, which might allow a remote attacker to cause a denial of service if an application
    is affected by the performance of a dictionary containing IPv4Interface or IPv6Interface objects, and this
    attacker can cause many dictionary entries to be created. (CVE-2020-14422)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1484.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20907");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14422");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python3' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'python3-3.7.9-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python3-3.7.9-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'python3-3.7.9-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python3-debug-3.7.9-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python3-debug-3.7.9-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'python3-debug-3.7.9-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python3-debuginfo-3.7.9-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python3-debuginfo-3.7.9-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'python3-debuginfo-3.7.9-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python3-devel-3.7.9-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python3-devel-3.7.9-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'python3-devel-3.7.9-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python3-libs-3.7.9-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python3-libs-3.7.9-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'python3-libs-3.7.9-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python3-test-3.7.9-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python3-test-3.7.9-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'python3-test-3.7.9-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python3-tkinter-3.7.9-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python3-tkinter-3.7.9-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'python3-tkinter-3.7.9-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python3-tools-3.7.9-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python3-tools-3.7.9-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'python3-tools-3.7.9-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3 / python3-debug / python3-debuginfo / etc");
}
