#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1319. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77979);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4002");
  script_xref(name:"RHSA", value:"2014:1319");

  script_name(english:"RHEL 6 / 7 : xerces-j2 (RHSA-2014:1319)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xerces-j2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Apache Xerces for Java (Xerces-J) is a high performance, standards
compliant, validating XML parser written in Java. The xerces-j2
packages provide Xerces-J version 2.

A resource consumption issue was found in the way Xerces-J handled XML
declarations. A remote attacker could use an XML document with a
specially crafted declaration using a long pseudo-attribute name that,
when parsed by an application using Xerces-J, would cause that
application to use an excessive amount of CPU. (CVE-2013-4002)

All xerces-j2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. Applications
using the Xerces-J must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:1319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4002"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-javadoc-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-javadoc-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-javadoc-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-javadoc-xni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1319";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-debuginfo-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-debuginfo-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-debuginfo-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-demo-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-demo-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-demo-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-javadoc-apis-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-javadoc-apis-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-javadoc-apis-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-javadoc-impl-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-javadoc-impl-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-javadoc-impl-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-javadoc-other-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-javadoc-other-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-javadoc-other-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-javadoc-xni-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-javadoc-xni-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-javadoc-xni-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-scripts-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-scripts-2.7.1-12.7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-scripts-2.7.1-12.7.el6_5")) flag++;


  if (rpm_check(release:"RHEL7", reference:"xerces-j2-2.11.0-17.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xerces-j2-demo-2.11.0-17.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xerces-j2-javadoc-2.11.0-17.el7_0")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-j2 / xerces-j2-debuginfo / xerces-j2-demo / etc");
  }
}
