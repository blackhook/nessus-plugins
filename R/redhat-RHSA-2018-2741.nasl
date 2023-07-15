#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2741. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117771);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-2582",
    "CVE-2017-7536",
    "CVE-2018-1336",
    "CVE-2018-10237"
  );
  script_xref(name:"RHSA", value:"2018:2741");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"RHEL 7 : JBoss EAP (RHSA-2018:2741)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update is now available for Red Hat JBoss Enterprise Application
Platform 6.4 for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform is a platform for Java
applications based on the JBoss Application Server.

This release of Red Hat JBoss Enterprise Application Platform 6.4.21
serves as a replacement for Red Hat JBoss Enterprise Application
Platform 6.4.20, and includes bug fixes and enhancements, which are
documented in the Release Notes document linked to in the References.

Security Fix(es) :

* hibernate-validator: Privilege escalation when running under the
security manager (CVE-2017-7536)

* guava: Unbounded memory allocation in AtomicDoubleArray and
CompoundOrdering classes allow remote attackers to cause a denial of
service (CVE-2018-10237)

* picketlink: The fix for CVE-2017-2582 breaks the feature of
attribute replacement with system property in picketlink.xml
(CVE-2017-2582)

* jbossweb: tomcat: A bug in the UTF-8 decoder can lead to DoS
(CVE-2018-1336)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

The CVE-2017-2582 issue was discovered by Hynek Mlnarik (Red Hat) and
the CVE-2017-7536 issue was discovered by Gunnar Morling (Red Hat).");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/documentation/en-US/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:2741");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-2582");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-7536");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1336");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10237");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7536");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-xc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:guava-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-validator");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-modules-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-product-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-standalone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-welcome-content-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-eap6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2018:2741";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL7", reference:"codehaus-jackson-1.9.9-14.redhat_7.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"codehaus-jackson-core-asl-1.9.9-14.redhat_7.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"codehaus-jackson-jaxrs-1.9.9-14.redhat_7.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"codehaus-jackson-mapper-asl-1.9.9-14.redhat_7.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"codehaus-jackson-xc-1.9.9-14.redhat_7.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"guava-libraries-13.0.1-5.redhat_3.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"hibernate4-validator-4.3.4-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"hornetq-2.3.25-27.SP28_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-common-api-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-common-impl-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-common-spi-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-core-api-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-core-impl-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-deployers-common-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-jdbc-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-spec-api-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ironjacamar-validator-eap6-1.0.42-2.Final_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-appclient-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-cli-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-client-all-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-clustering-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-cmp-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-configadmin-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-connector-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-controller-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-controller-client-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-core-security-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-deployment-repository-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-deployment-scanner-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-domain-http-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-domain-management-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-ee-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-ee-deployment-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-ejb3-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-embedded-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-host-controller-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jacorb-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jaxr-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jaxrs-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jdr-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jmx-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jpa-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jsf-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-jsr77-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-logging-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-mail-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-management-client-content-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-messaging-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-modcluster-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-naming-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-network-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-osgi-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-osgi-configadmin-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-osgi-service-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-picketlink-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-platform-mbean-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-pojo-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-process-controller-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-protocol-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-remoting-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-sar-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-security-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-server-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-system-jmx-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-threads-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-transactions-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-version-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-web-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-webservices-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-weld-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-as-xts-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-ejb-client-1.0.41-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-modules-1.3.11-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-vfs2-3.2.13-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jboss-xnio-base-3.0.17-1.GA_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-appclient-7.5.21-2.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-bundles-7.5.21-2.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-core-7.5.21-2.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-domain-7.5.21-2.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-javadocs-7.5.21-2.Final_redhat_1.2.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-modules-eap-7.5.21-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-product-eap-7.5.21-2.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-standalone-7.5.21-2.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossas-welcome-content-eap-7.5.21-2.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbossweb-7.5.29-1.Final_redhat_1.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"picketlink-bindings-2.5.4-23.SP18_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"picketlink-federation-2.5.4-21.SP18_redhat_2.1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"xerces-j2-eap6-2.9.1-19.redhat_8.1.ep6.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "codehaus-jackson / codehaus-jackson-core-asl / etc");
  }
}
