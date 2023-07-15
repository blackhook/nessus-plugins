#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2640. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112249);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2016-7046");
  script_xref(name:"RHSA", value:"2016:2640");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2016:2640)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that provide Red Hat JBoss Enterprise Application
Platform 7.0.3 that fix several bugs and add various enhancements that
are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform 7 is an application
server that serves as a middleware platform and is built on open
standards and compliant with the Java EE 7 specification.

This release serves as a replacement for Red Hat JBoss Enterprise
Application Platform 7.0.2. It includes bug fixes and enhancements.
Refer to the JBoss Enterprise Application Platform 7.0.3 Release Notes
linked to in the References section for information about the most
significant bug fixes and enhancements included in this release.

Security Fix(es) :

* It was discovered that a long URL sent to EAP 7 Server operating as
a reverse proxy with default buffer sizes causes a Denial of Service.
(CVE-2016-7046)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7046"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xerces-j2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/04");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:2640";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"eap7-jboss"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-5.0.11-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-core-5.0.11-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-entitymanager-5.0.11-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-envers-5.0.11-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-infinispan-5.0.11-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-java8-5.0.11-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-remoting-4.0.21-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-xnio-base-3.4.0-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-undertow-1.3.25-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-7.0.3-4.GA_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-javadocs-7.0.3-2.GA_redhat_3.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-modules-7.0.3-4.GA_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-xerces-j2-2.11.0-24.SP5_redhat_1.1.ep7.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eap7-hibernate / eap7-hibernate-core / eap7-hibernate-entitymanager / etc");
  }
}
