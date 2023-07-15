#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0067 and 
# CentOS Errata and Security Advisory 2016:0067 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88386);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_xref(name:"RHSA", value:"2016:0067");

  script_name(english:"CentOS 5 / 6 / 7 : java-1.6.0-openjdk (CESA-2016:0067)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.6.0-openjdk packages provide the OpenJDK 6 Java Runtime
Environment and the OpenJDK 6 Java Software Development Kit.

An out-of-bounds write flaw was found in the JPEG image format decoder
in the AWT component in OpenJDK. A specially crafted JPEG image could
cause a Java application to crash or, possibly execute arbitrary code.
An untrusted Java application or applet could use this flaw to bypass
Java sandbox restrictions. (CVE-2016-0483)

An integer signedness issue was found in the font parsing code in the
2D component in OpenJDK. A specially crafted font file could possibly
cause the Java Virtual Machine to execute arbitrary code, allowing an
untrusted Java application or applet to bypass Java sandbox
restrictions. (CVE-2016-0494)

It was discovered that the JAXP component in OpenJDK did not properly
enforce the totalEntitySizeLimit limit. An attacker able to make a
Java application process a specially crafted XML file could use this
flaw to make the application consume an excessive amount of memory.
(CVE-2016-0466)

Multiple flaws were discovered in the Networking and JMX components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2016-0402,
CVE-2016-0448)

Note: This update also disallows the use of the MD5 hash algorithm in
the certification path processing. The use of MD5 can be re-enabled by
removing MD5 from the jdk.certpath.disabledAlgorithms security
property defined in the java.security file.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-January/021626.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?baa312c1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-January/021627.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f74f44d2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-January/021628.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ddeed7a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0483");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

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
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.38-1.13.10.0.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.38-1.13.10.0.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.38-1.13.10.0.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.38-1.13.10.0.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.38-1.13.10.0.el5_11")) flag++;

if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-1.6.0.38-1.13.10.0.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-demo-1.6.0.38-1.13.10.0.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-devel-1.6.0.38-1.13.10.0.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.38-1.13.10.0.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-src-1.6.0.38-1.13.10.0.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.38-1.13.10.0.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.38-1.13.10.0.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.38-1.13.10.0.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.38-1.13.10.0.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.38-1.13.10.0.el7_2")) flag++;


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
