#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:2242 and 
# Oracle Linux Security Advisory ELSA-2018-2242 respectively.
#

include("compat.inc");

if (description)
{
  script_id(111254);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2018-2952");
  script_xref(name:"RHSA", value:"2018:2242");

  script_name(english:"Oracle Linux 7 : java-1.8.0-openjdk (ELSA-2018-2242)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:2242 :

An update for java-1.8.0-openjdk is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es) :

* OpenJDK: insufficient index validation in PatternSyntaxException
getMessage () (Concurrency, 8199547) (CVE-2018-2952)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

Bug Fix(es) :

* This update applies changes from OpenJDK upstream version 8u172,
which provides a number of bug fixes over the previous version, 8u171.
(BZ# 1588364)

* OpenJDK was recently updated to support reading the system
certificate authority database (cacerts) directly. As an unintended
consequence, this removed the ability to read certificates from the
user-provided jssecacerts file. With this update, that ability is
restored by reading from that file first, if available. (BZ#1593737)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-July/007905.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.8.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.181-3.b13.el7_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
