#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:1278 and 
# Oracle Linux Security Advisory ELSA-2018-1278 respectively.
#

include("compat.inc");

if (description)
{
  script_id(109542);
  script_version("1.7");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2815");
  script_xref(name:"RHSA", value:"2018:1278");

  script_name(english:"Oracle Linux 7 : java-1.7.0-openjdk (ELSA-2018-1278)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:1278 :

An update for java-1.7.0-openjdk is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

Security Fix(es) :

* OpenJDK: incorrect handling of Reference clones can lead to sandbox
bypass (Hotspot, 8192025) (CVE-2018-2814)

* OpenJDK: unrestricted deserialization of data from JCEKS key stores
(Security, 8189997) (CVE-2018-2794)

* OpenJDK: insufficient consistency checks in deserialization of
multiple classes (Security, 8189977) (CVE-2018-2795)

* OpenJDK: unbounded memory allocation during deserialization in
PriorityBlockingQueue (Concurrency, 8189981) (CVE-2018-2796)

* OpenJDK: unbounded memory allocation during deserialization in
TabularDataSupport (JMX, 8189985) (CVE-2018-2797)

* OpenJDK: unbounded memory allocation during deserialization in
Container (AWT, 8189989) (CVE-2018-2798)

* OpenJDK: unbounded memory allocation during deserialization in
NamedNodeMapImpl (JAXP, 8189993) (CVE-2018-2799)

* OpenJDK: RMI HTTP transport enabled by default (RMI, 8193833)
(CVE-2018-2800)

* OpenJDK: unbounded memory allocation during deserialization in
StubIORImpl (Serialization, 8192757) (CVE-2018-2815)

* OpenJDK: incorrect merging of sections in the JAR manifest
(Security, 8189969) (CVE-2018-2790)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-May/007664.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/03");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.181-2.6.14.5.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.181-2.6.14.5.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.181-2.6.14.5.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.181-2.6.14.5.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.181-2.6.14.5.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-javadoc-1.7.0.181-2.6.14.5.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.181-2.6.14.5.0.1.el7")) flag++;


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
