#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1506.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149866);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/30");

  script_cve_id("CVE-2021-31799");
  script_xref(name:"ALAS", value:"2021-1506");

  script_name(english:"Amazon Linux AMI : ruby24 (ALAS-2021-1506)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of ruby24 installed on the remote host is prior to 2.4.10-2.15. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2021-1506 advisory. Note that Nessus has not tested for this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1506.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-31799");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ruby24' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31799");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-minitest5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'ruby24-2.4.10-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby24-2.4.10-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby24-debuginfo-2.4.10-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby24-debuginfo-2.4.10-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby24-devel-2.4.10-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby24-devel-2.4.10-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby24-doc-2.4.10-2.15.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby24-irb-2.4.10-2.15.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby24-libs-2.4.10-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby24-libs-2.4.10-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-bigdecimal-1.3.2-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-bigdecimal-1.3.2-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-did_you_mean-1.1.0-2.15.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-io-console-0.4.6-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-io-console-0.4.6-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-json-2.0.4-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-json-2.0.4-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-minitest5-5.10.1-2.15.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-net-telnet-0.1.1-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-net-telnet-0.1.1-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-power_assert-0.4.1-2.15.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-psych-2.2.2-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-psych-2.2.2-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-rdoc-5.0.1-2.15.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-test-unit-3.2.3-2.15.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-xmlrpc-0.2.1-2.15.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem24-xmlrpc-0.2.1-2.15.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems24-2.6.14.4-2.15.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems24-devel-2.6.14.4-2.15.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby24 / ruby24-debuginfo / ruby24-devel / etc");
}