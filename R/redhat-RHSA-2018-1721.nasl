#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1721. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110115);
  script_version("1.8");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-2783", "CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800");
  script_xref(name:"RHSA", value:"2018:1721");

  script_name(english:"RHEL 7 : java-1.8.0-ibm (RHSA-2018:1721)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.8.0-ibm is now available for Red Hat Enterprise
Linux 7 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

IBM Java SE version 8 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update upgrades IBM Java SE 8 to version 8 SR5-FP15.

Security Fix(es) :

* OpenJDK: unrestricted deserialization of data from JCEKS key stores
(Security, 8189997) (CVE-2018-2794)

* Oracle JDK: unspecified vulnerability fixed in 6u191, 7u171, and
8u161 (Security) (CVE-2018-2783)

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

* OpenJDK: incorrect merging of sections in the JAR manifest
(Security, 8189969) (CVE-2018-2790)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2800"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:1721";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-ibm-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-ibm-demo-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-demo-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-ibm-devel-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-devel-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-ibm-jdbc-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-jdbc-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-plugin-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-ibm-src-1.8.0.5.15-1jpp.5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-src-1.8.0.5.15-1jpp.5.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-ibm / java-1.8.0-ibm-demo / java-1.8.0-ibm-devel / etc");
  }
}
