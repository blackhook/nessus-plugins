#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0723 and 
# CentOS Errata and Security Advisory 2016:0723 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91018);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2016-0686",
    "CVE-2016-0687",
    "CVE-2016-0695",
    "CVE-2016-3425",
    "CVE-2016-3427"
  );
  script_xref(name:"RHSA", value:"2016:0723");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"CentOS 5 / 6 / 7 : java-1.6.0-openjdk (CESA-2016:0723)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for java-1.6.0-openjdk is now available for Red Hat
Enterprise Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.6.0-openjdk packages provide the OpenJDK 6 Java Runtime
Environment and the OpenJDK 6 Java Software Development Kit.

Security Fix(es) :

* Multiple flaws were discovered in the Serialization and Hotspot
components in OpenJDK. An untrusted Java application or applet could
use these flaws to completely bypass Java sandbox restrictions.
(CVE-2016-0686, CVE-2016-0687)

* It was discovered that the RMI server implementation in the JMX
component in OpenJDK did not restrict which classes can be
deserialized when deserializing authentication credentials. A remote,
unauthenticated attacker able to connect to a JMX port could possibly
use this flaw to trigger deserialization flaws. (CVE-2016-3427)

* It was discovered that the JAXP component in OpenJDK failed to
properly handle Unicode surrogate pairs used as part of the XML
attribute values. Specially crafted XML input could cause a Java
application to use an excessive amount of memory when parsed.
(CVE-2016-3425)

* It was discovered that the Security component in OpenJDK failed to
check the digest algorithm strength when generating DSA signatures.
The use of a digest weaker than the key strength could lead to the
generation of signatures that were weaker than expected.
(CVE-2016-0695)");
  # https://lists.centos.org/pipermail/centos-announce/2016-May/021861.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a03f6c1");
  # https://lists.centos.org/pipermail/centos-announce/2016-May/021862.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ca53ca8");
  # https://lists.centos.org/pipermail/centos-announce/2016-May/021863.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90d8c9f5");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.6.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3427");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-0687");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.39-1.13.11.0.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.39-1.13.11.0.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.39-1.13.11.0.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.39-1.13.11.0.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.39-1.13.11.0.el5_11")) flag++;

if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-1.6.0.39-1.13.11.0.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-demo-1.6.0.39-1.13.11.0.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-devel-1.6.0.39-1.13.11.0.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.39-1.13.11.0.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-src-1.6.0.39-1.13.11.0.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.39-1.13.11.0.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.39-1.13.11.0.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.39-1.13.11.0.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.39-1.13.11.0.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.39-1.13.11.0.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
