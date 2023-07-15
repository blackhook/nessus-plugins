#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2276. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111486);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-10862", "CVE-2018-8039");
  script_xref(name:"RHSA", value:"2018:2276");

  script_name(english:"RHEL 6 / 7 : JBoss EAP (RHSA-2018:2276)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security update is now available for Red Hat JBoss Enterprise
Application Platform from the Customer Portal.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform 7 is a platform for Java
applications based on Wildfly.

This asynchronous patch is a security update for wildfly-core and
apache-cxf packages in Red Hat JBoss Enterprise Application Platform
7.1

Security Fix(es) :

* apache-cxf: TLS hostname verification does not work correctly with
com.sun.net.ssl.* (CVE-2018-8039)

* wildfly-core: Path traversal can allow the extraction of .war
archives to write arbitrary files. (CVE-2018-10862)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-8039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10862"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-policy-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/02");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:2276";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"eap7-jboss") || rpm_exists(release:"RHEL7", rpm:"eap7-jboss"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-3.1.16-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-rt-3.1.16-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-services-3.1.16-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-tools-3.1.16-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-7.1.3-4.GA_redhat_3.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-modules-7.1.3-4.GA_redhat_3.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-2.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-bindings-2.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-policy-2.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-ws-security-common-2.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-ws-security-dom-2.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-ws-security-policy-stax-2.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-ws-security-stax-2.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-xml-security-2.0.10-1.redhat_1.1.ep7.el6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-3.1.16-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-rt-3.1.16-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-services-3.1.16-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-tools-3.1.16-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-7.1.3-4.GA_redhat_3.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-modules-7.1.3-4.GA_redhat_3.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-2.1.12-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-bindings-2.1.12-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-policy-2.1.12-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-common-2.1.12-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-dom-2.1.12-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-policy-stax-2.1.12-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-stax-2.1.12-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-xml-security-2.0.10-1.redhat_1.1.ep7.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eap7-apache-cxf / eap7-apache-cxf-rt / eap7-apache-cxf-services / etc");
  }
}
