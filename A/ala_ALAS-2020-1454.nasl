##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1454.
##

include('compat.inc');

if (description)
{
  script_id(142975);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/18");

  script_cve_id("CVE-2020-26116");
  script_xref(name:"ALAS", value:"2020-1454");

  script_name(english:"Amazon Linux AMI : python27 (ALAS-2020-1454)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2020-1454 advisory.

  - http.client in Python 3.x before 3.5.10, 3.6.x before 3.6.12, 3.7.x before 3.7.9, and 3.8.x before 3.8.5
    allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR
    and LF control characters in the first argument of HTTPConnection.request. (CVE-2020-26116)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1454.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26116");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python27' to update your system.
 Run 'yum update python34' to update your system.
 Run 'yum update python35' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26116");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'python27-2.7.18-2.140.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-2.7.18-2.140.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-debuginfo-2.7.18-2.140.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-debuginfo-2.7.18-2.140.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-devel-2.7.18-2.140.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-devel-2.7.18-2.140.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-libs-2.7.18-2.140.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-libs-2.7.18-2.140.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-test-2.7.18-2.140.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-test-2.7.18-2.140.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-tools-2.7.18-2.140.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-tools-2.7.18-2.140.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python34-3.4.10-1.53.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python34-3.4.10-1.53.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python34-debuginfo-3.4.10-1.53.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python34-debuginfo-3.4.10-1.53.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python34-devel-3.4.10-1.53.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python34-devel-3.4.10-1.53.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python34-libs-3.4.10-1.53.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python34-libs-3.4.10-1.53.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python34-test-3.4.10-1.53.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python34-test-3.4.10-1.53.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python34-tools-3.4.10-1.53.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python34-tools-3.4.10-1.53.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python35-3.5.10-1.29.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python35-3.5.10-1.29.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python35-debuginfo-3.5.10-1.29.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python35-debuginfo-3.5.10-1.29.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python35-devel-3.5.10-1.29.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python35-devel-3.5.10-1.29.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python35-libs-3.5.10-1.29.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python35-libs-3.5.10-1.29.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python35-test-3.5.10-1.29.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python35-test-3.5.10-1.29.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python35-tools-3.5.10-1.29.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python35-tools-3.5.10-1.29.amzn1', 'cpu':'x86_64', 'release':'ALA'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python27 / python27-debuginfo / python27-devel / etc");
}