#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1064.
#

include("compat.inc");

if (description)
{
  script_id(112089);
  script_version("1.2");
  script_cvs_date("Date: 2018/08/31 12:25:01");

  script_cve_id("CVE-2018-2952");
  script_xref(name:"ALAS", value:"2018-1064");

  script_name(english:"Amazon Linux 2 : java-1.7.0-openjdk (ALAS-2018-1064)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Concurrency). Difficult to exploit
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise Java SE, Java SE Embedded, JRockit.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a partial denial of service (partial DOS) of Java SE,
Java SE Embedded, JRockit. Note: Applies to client and server
deployment of Java. This vulnerability can be exploited through
sandboxed Java Web Start applications and sandboxed Java applets. It
can also be exploited by supplying data to APIs in the specified
Component without using sandboxed Java Web Start applications or
sandboxed Java applets, such as through a web service. CVSS 3.0 Base
Score 3.7 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2018-2952)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1064.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"java-1.7.0-openjdk-1.7.0.191-2.6.15.4.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.7.0-openjdk-accessibility-1.7.0.191-2.6.15.4.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.191-2.6.15.4.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.7.0-openjdk-demo-1.7.0.191-2.6.15.4.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.7.0-openjdk-devel-1.7.0.191-2.6.15.4.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.7.0-openjdk-headless-1.7.0.191-2.6.15.4.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.7.0-openjdk-javadoc-1.7.0.191-2.6.15.4.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.7.0-openjdk-src-1.7.0.191-2.6.15.4.amzn2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-accessibility / etc");
}
