#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1550. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100982);
  script_version("3.7");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-5018", "CVE-2016-6796", "CVE-2017-2595");
  script_xref(name:"RHSA", value:"2017:1550");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2017:1550)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat JBoss Enterprise Application
Platform 6.4 for RHEL 5.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform is a platform for Java
applications based on the JBoss Application Server.

This release of Red Hat JBoss Enterprise Application Platform 6.4.16
serves as a replacement for Red Hat JBoss Enterprise Application
Platform 6.4.15, and includes bug fixes and enhancements, which are
documented in the Release Notes document linked to in the References.

Security Fix(es) :

* It was found that the log file viewer in Red Hat JBoss Enterprise
Application 6 and 7 allows arbitrary file read to authenticated user
via path traversal. (CVE-2017-2595)

* It was discovered that a malicious web application could bypass a
configured SecurityManager via a Tomcat utility method that was
accessible to web applications. (CVE-2016-5018)

* It was discovered that a malicious web application could bypass a
configured SecurityManager via manipulation of the configuration
parameters for the JSP Servlet. (CVE-2016-6796)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-5018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-6796.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-2595.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-1550.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-impl-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-spi-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-impl-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-deployers-common-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-jdbc-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-spec-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-validator-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-client-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-clustering");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-connector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-controller-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-core-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-deployment-repository");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-deployment-scanner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-domain-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-domain-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-ee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-ee-deployment");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-ejb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-host-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jaxr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jpa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jsr77");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-management-client-content");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-modcluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-osgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-osgi-configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-osgi-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-picketlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-platform-mbean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-pojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-process-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-sar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-system-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-transactions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-webservices");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-weld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-xts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-modules-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-product-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-standalone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-welcome-content-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 Tenable Network Security, Inc.");
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
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1550";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"hornetq-2.3.25-21.SP19_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-common-api-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-common-impl-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-common-spi-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-core-api-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-core-impl-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-deployers-common-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-jdbc-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-spec-api-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-validator-eap6-1.0.39-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-appclient-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-cli-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-client-all-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-clustering-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-cmp-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-configadmin-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-connector-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-console-2.5.17-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-controller-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-controller-client-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-core-security-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-deployment-repository-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-deployment-scanner-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-domain-http-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-domain-management-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ee-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ee-deployment-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ejb3-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-embedded-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-host-controller-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jacorb-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jaxr-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jaxrs-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jdr-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jmx-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jpa-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jsf-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jsr77-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-logging-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-mail-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-management-client-content-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-messaging-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-modcluster-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-naming-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-network-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-configadmin-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-service-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-picketlink-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-platform-mbean-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-pojo-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-process-controller-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-protocol-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-remoting-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-sar-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-security-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-server-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-system-jmx-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-threads-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-transactions-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-version-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-web-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-webservices-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-weld-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-xts-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-hal-2.5.17-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-logmanager-1.5.7-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-marshalling-1.4.10-2.SP2_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-modules-1.3.9-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-appclient-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-bundles-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-core-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-domain-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-javadocs-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-modules-eap-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-product-eap-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-standalone-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-welcome-content-eap-7.5.16-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.17.42-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-7.5.23-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jgroups-3.2.17-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"picketbox-4.1.6-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-2.3.20-1.Final_redhat_1.1.ep6.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hornetq / ironjacamar-common-api-eap6 / etc");
  }
}
