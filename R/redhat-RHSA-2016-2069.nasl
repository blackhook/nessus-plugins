#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2069. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112248);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2016-3092");
  script_xref(name:"RHSA", value:"2016:2069");

  script_name(english:"RHEL 7 : JBoss EAP (RHSA-2016:2069)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that provide Red Hat JBoss Enterprise Application
Platform 6.4.11, fix several bugs, and add various enhancements are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

This release serves as a replacement for Red Hat JBoss Enterprise
Application Platform 6.4.10. It includes bug fixes and enhancements.
Documentation for these changes will be available shortly from the Red
Hat JBoss Enterprise Application Platform 6.4.11 Release Notes, linked
to in the References.

All users of Red Hat JBoss Enterprise Application Platform 6.4 on Red
Hat Enterprise Linux 7 are advised to upgrade to these updated
packages. The JBoss server process must be restarted for the update to
take effect.

Security Fix(es) :

* A denial of service vulnerability was identified in Commons
FileUpload that occurred when the length of the multipart boundary was
just below the size of the buffer (4096 bytes) used to read the
uploaded file if the boundary was the typical tens of bytes long.
(CVE-2016-3092)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3092"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-client-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-clustering");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-connector");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remote-naming");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/17");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:2069";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL7", reference:"apache-cxf-2.7.18-4.SP3_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"hornetq-2.3.25-16.SP14_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-appclient-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-cli-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-client-all-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-clustering-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-cmp-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-configadmin-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-connector-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-controller-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-controller-client-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-core-security-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-deployment-repository-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-deployment-scanner-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-domain-http-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-domain-management-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-ee-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-ee-deployment-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-ejb3-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-embedded-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-host-controller-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jacorb-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jaxr-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jaxrs-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jdr-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jmx-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jpa-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jsf-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jsr77-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-logging-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-mail-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-management-client-content-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-messaging-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-modcluster-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-naming-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-network-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-osgi-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-osgi-configadmin-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-osgi-service-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-picketlink-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-platform-mbean-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-pojo-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-process-controller-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-protocol-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-remoting-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-sar-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-security-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-server-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-system-jmx-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-threads-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-transactions-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-version-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-web-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-webservices-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-weld-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-xts-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-remote-naming-1.0.13-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-appclient-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-bundles-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-core-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-domain-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-javadocs-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-modules-eap-7.5.11-2.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-product-eap-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-standalone-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-welcome-content-eap-7.5.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossts-4.17.35-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossweb-7.5.19-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"picketlink-bindings-2.5.4-13.SP11_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"picketlink-federation-2.5.4-13.SP11_redhat_1.1.ep6.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-cxf / hornetq / jboss-as-appclient / jboss-as-cli / etc");
  }
}
