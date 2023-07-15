#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2569. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112132);
  script_version("1.10");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-12539", "CVE-2018-1517", "CVE-2018-1656", "CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2973");
  script_xref(name:"RHSA", value:"2018:2569");

  script_name(english:"RHEL 7 : java-1.7.1-ibm (RHSA-2018:2569)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.7.1-ibm is now available for Red Hat Enterprise
Linux 7 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

IBM Java SE version 7 Release 1 includes the IBM Java Runtime
Environment and the IBM Java Software Development Kit.

This update upgrades IBM Java SE 7 to version 7R1 SR4-FP30.

Security Fix(es) :

* IBM JDK: privilege escalation via insufficiently restricted access
to Attach API (CVE-2018-12539)

* IBM JDK: DoS in the java.math component (CVE-2018-1517)

* IBM JDK: path traversal flaw in the Diagnostic Tooling Framework
(CVE-2018-1656)

* Oracle JDK: unspecified vulnerability fixed in 6u201, 7u191, 8u181,
and 10.0.2 (Libraries) (CVE-2018-2940)

* OpenJDK: insufficient index validation in PatternSyntaxException
getMessage () (Concurrency, 8199547) (CVE-2018-2952)

* Oracle JDK: unspecified vulnerability fixed in 6u201, 7u191, 8u181,
and 10.0.2 (JSSE) (CVE-2018-2973)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-12539"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");
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
  rhsa = "RHSA-2018:2569";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-demo-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-demo-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-devel-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-devel-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-jdbc-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-jdbc-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-plugin-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-src-1.7.1.4.30-1jpp.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-src-1.7.1.4.30-1jpp.1.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.1-ibm / java-1.7.1-ibm-demo / java-1.7.1-ibm-devel / etc");
  }
}
