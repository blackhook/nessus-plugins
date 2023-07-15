#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1426.
#

include('compat.inc');

if (description)
{
  script_id(140094);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2013-0269", "CVE-2020-10663");
  script_bugtraq_id(57899);
  script_xref(name:"ALAS", value:"2020-1426");

  script_name(english:"Amazon Linux AMI : ruby19 (ALAS-2020-1426)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS-2020-1426 advisory.

  - The JSON gem before 1.5.5, 1.6.x before 1.6.8, and 1.7.x before 1.7.7 for Ruby allows remote attackers to
    cause a denial of service (resource consumption) or bypass the mass assignment protection mechanism via a
    crafted JSON document that triggers the creation of arbitrary Ruby symbols or certain internal objects, as
    demonstrated by conducting a SQL injection attack against Ruby on Rails, aka Unsafe Object Creation
    Vulnerability. (CVE-2013-0269)

  - The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.4 through 2.4.9, 2.5 through 2.5.7, and 2.6 through
    2.6.5, has an Unsafe Object Creation Vulnerability. This is quite similar to CVE-2013-0269, but does not
    rely on poor garbage-collection behavior within Ruby. Specifically, use of JSON parsing methods can lead
    to creation of a malicious object within the interpreter, with adverse effects that are application-
    dependent. (CVE-2020-10663)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1426.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10663");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ruby19' to update your system.
 Run 'yum update ruby21' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0269");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem21-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem21-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem21-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems19-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems21-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'ruby19-1.9.3.551-33.71.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby19-1.9.3.551-33.71.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby19-debuginfo-1.9.3.551-33.71.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby19-debuginfo-1.9.3.551-33.71.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby19-devel-1.9.3.551-33.71.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby19-devel-1.9.3.551-33.71.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby19-doc-1.9.3.551-33.71.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby19-doc-1.9.3.551-33.71.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby19-irb-1.9.3.551-33.71.amzn1', 'release':'ALA'},
    {'reference':'ruby19-libs-1.9.3.551-33.71.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby19-libs-1.9.3.551-33.71.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby21-2.1.9-1.23.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby21-2.1.9-1.23.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby21-debuginfo-2.1.9-1.23.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby21-debuginfo-2.1.9-1.23.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby21-devel-2.1.9-1.23.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby21-devel-2.1.9-1.23.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby21-doc-2.1.9-1.23.amzn1', 'release':'ALA'},
    {'reference':'ruby21-irb-2.1.9-1.23.amzn1', 'release':'ALA'},
    {'reference':'ruby21-libs-2.1.9-1.23.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby21-libs-2.1.9-1.23.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem19-bigdecimal-1.1.0-33.71.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem19-bigdecimal-1.1.0-33.71.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem19-io-console-0.3-33.71.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem19-io-console-0.3-33.71.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem19-json-1.5.5-33.71.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem19-json-1.5.5-33.71.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem19-minitest-2.5.1-33.71.amzn1', 'release':'ALA'},
    {'reference':'rubygem19-rake-0.9.2.2-33.71.amzn1', 'release':'ALA'},
    {'reference':'rubygem19-rdoc-3.9.5-33.71.amzn1', 'release':'ALA'},
    {'reference':'rubygem21-bigdecimal-1.2.4-1.23.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem21-bigdecimal-1.2.4-1.23.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem21-io-console-0.4.3-1.23.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem21-io-console-0.4.3-1.23.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem21-psych-2.0.5-1.23.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem21-psych-2.0.5-1.23.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygems19-1.8.23.2-33.71.amzn1', 'release':'ALA'},
    {'reference':'rubygems19-devel-1.8.23.2-33.71.amzn1', 'release':'ALA'},
    {'reference':'rubygems21-2.2.5-1.23.amzn1', 'release':'ALA'},
    {'reference':'rubygems21-devel-2.2.5-1.23.amzn1', 'release':'ALA'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby19 / ruby19-debuginfo / ruby19-devel / etc");
}
