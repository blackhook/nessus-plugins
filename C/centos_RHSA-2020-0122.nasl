#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:0122 and 
# CentOS Errata and Security Advisory 2020:0122 respectively.
#

include("compat.inc");

if (description)
{
  script_id(133098);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/24");

  script_cve_id("CVE-2020-2583", "CVE-2020-2590", "CVE-2020-2593", "CVE-2020-2601", "CVE-2020-2604", "CVE-2020-2654", "CVE-2020-2655");
  script_xref(name:"RHSA", value:"2020:0122");

  script_name(english:"CentOS 7 : java-11-openjdk (CESA-2020:0122)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-11-openjdk is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-11-openjdk packages provide the OpenJDK 11 Java Runtime
Environment and the OpenJDK 11 Java Software Development Kit.

Security Fix(es) :

* OpenJDK: Use of unsafe RSA-MD5 checkum in Kerberos TGS (Security,
8229951) (CVE-2020-2601)

* OpenJDK: Serialization filter changes via jdk.serialFilter property
modification (Serialization, 8231422) (CVE-2020-2604)

* OpenJDK: Improper checks of SASL message properties in GssKrb5Base
(Security, 8226352) (CVE-2020-2590)

* OpenJDK: Incorrect isBuiltinStreamHandler causing URL normalization
issues (Networking, 8228548) (CVE-2020-2593)

* OpenJDK: Excessive memory usage in OID processing in X.509
certificate parsing (Libraries, 8234037) (CVE-2020-2654)

* OpenJDK: Incorrect handling of unexpected CertificateVerify TLS
handshake messages (JSSE, 8231780) (CVE-2020-2655)

* OpenJDK: Incorrect exception processing during deserialization in
BeanContextSupport (Serialization, 8224909) (CVE-2020-2583)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  # https://lists.centos.org/pipermail/centos-announce/2020-January/035605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99e697c9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-11-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-jmods-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-debug-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-demo-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-demo-debug-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-devel-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-devel-debug-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-headless-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-headless-debug-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-debug-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-debug-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-jmods-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-jmods-debug-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-src-11.0.6.10-1.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-src-debug-11.0.6.10-1.el7_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-debug / java-11-openjdk-demo / etc");
}
