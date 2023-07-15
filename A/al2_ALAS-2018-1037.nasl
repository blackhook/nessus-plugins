#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1037.
#

include("compat.inc");

if (description)
{
  script_id(110454);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639");
  script_xref(name:"ALAS", value:"2018-1037");

  script_name(english:"Amazon Linux 2 : java-1.7.0-openjdk (ALAS-2018-1037) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of Load & Store
instructions (a commonly used performance optimization). It relies on
the presence of a precisely-defined instruction sequence in the
privileged code as well as the fact that memory read from address to
which a recent memory write has occurred may see an older value and
subsequently cause an update into the microprocessor's data cache even
for speculatively executed instructions that never actually commit
(retire). As a result, an unprivileged attacker could use this flaw to
read privileged memory by conducting targeted cache side-channel
attacks.(CVE-2018-3639)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1037.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

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


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.181-2.6.14.8.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.181-2.6.14.8.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.181-2.6.14.8.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.181-2.6.14.8.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.181-2.6.14.8.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.181-2.6.14.8.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.7.0-openjdk-javadoc-1.7.0.181-2.6.14.8.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.181-2.6.14.8.amzn2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-accessibility / etc");
}
