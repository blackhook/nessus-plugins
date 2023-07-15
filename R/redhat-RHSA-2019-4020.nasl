#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:4020. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131524);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-14838",
    "CVE-2019-14843",
    "CVE-2019-9511",
    "CVE-2019-9512",
    "CVE-2019-9514",
    "CVE-2019-9515"
  );
  script_xref(name:"RHSA", value:"2019:4020");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"RHEL 8 : JBoss EAP (RHSA-2019:4020) (Data Dribble) (Ping Flood) (Reset Flood) (Settings Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update is now available for Red Hat JBoss Enterprise Application
Platform 7.2 for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform 7 is a platform for Java
applications based on the WildFly application runtime.

This release of Red Hat JBoss Enterprise Application Platform 7.2.5
serves as a replacement for Red Hat JBoss Enterprise Application
Platform 7.2.4, and includes bug fixes and enhancements. See the Red
Hat JBoss Enterprise Application Platform 7.2.5 Release Notes for
information about the most significant bug fixes and enhancements
included in this release.

Security Fix(es) :

* undertow: HTTP/2: large amount of data requests leads to denial of
service (CVE-2019-9511)

* undertow: HTTP/2: flood using PING frames results in unbounded
memory growth (CVE-2019-9512)

* undertow: HTTP/2: flood using HEADERS frames results in unbounded
memory growth (CVE-2019-9514)

* undertow: HTTP/2: flood using SETTINGS frames results in unbounded
memory growth (CVE-2019-9515)

* wildfly-core: Incorrect privileges for 'Monitor', 'Auditor' and
'Deployer' user by default (CVE-2019-14838)

* wildfly: wildfly-security-manager: security manager authorization
bypass (CVE-2019-14843)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/documentation/en-us/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:4020");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9511");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9512");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9514");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9515");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-14838");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-14843");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-byte-buddy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-genericjms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-msc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.1-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly11.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly12.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly12.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly13.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly14.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-simple-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-wildfly8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-client-microprofile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson2-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jose-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-binding-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-p-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-multipart-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-rxjava2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-spring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-validator-provider-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-yaml-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-linux-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-linux-x86_64-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-yasson");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:4020";
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

  if (! (rpm_exists(release:"RHEL8", rpm:"eap7-jboss"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL8", reference:"eap7-apache-cxf-3.2.10-1.redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-apache-cxf-rt-3.2.10-1.redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-apache-cxf-services-3.2.10-1.redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-apache-cxf-tools-3.2.10-1.redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-byte-buddy-1.9.11-1.redhat_00002.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-glassfish-jsf-2.3.5-5.SP3_redhat_00003.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-hal-console-3.0.17-2.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-hibernate-5.3.13-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-hibernate-core-5.3.13-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-hibernate-entitymanager-5.3.13-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-hibernate-envers-5.3.13-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-hibernate-java8-5.3.13-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-ironjacamar-1.4.18-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-ironjacamar-common-api-1.4.18-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-ironjacamar-common-impl-1.4.18-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-ironjacamar-common-spi-1.4.18-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-ironjacamar-core-api-1.4.18-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-ironjacamar-core-impl-1.4.18-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-ironjacamar-deployers-common-1.4.18-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-ironjacamar-jdbc-1.4.18-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-ironjacamar-validator-1.4.18-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-genericjms-2.0.2-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-msc-1.4.11-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-remoting-5.0.16-2.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-cli-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-core-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-eap6.4-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-eap6.4-to-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-eap7.0-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-eap7.0-to-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-eap7.1-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-eap7.1-to-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly10.0-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly10.0-to-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly10.1-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly10.1-to-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly11.0-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly11.0-to-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly12.0-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly12.0-to-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly13.0-server-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly14.0-server-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly8.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly8.2-to-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly9.0-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-server-migration-wildfly9.0-to-eap7.2-1.3.1-6.Final_redhat_00006.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-jboss-xnio-base-3.7.6-2.SP1_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketbox-5.0.3-6.Final_redhat_00005.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketbox-infinispan-5.0.3-6.Final_redhat_00005.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-api-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-bindings-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-common-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-config-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-federation-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-idm-api-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-idm-impl-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-idm-simple-schema-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-impl-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-picketlink-wildfly8-2.5.5-20.SP12_redhat_00009.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-atom-provider-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-cdi-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-client-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-client-microprofile-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-crypto-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-jackson-provider-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-jackson2-provider-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-jaxb-provider-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-jaxrs-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-jettison-provider-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-jose-jwt-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-jsapi-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-json-binding-provider-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-json-p-provider-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-multipart-provider-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-rxjava2-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-spring-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-validator-provider-11-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-resteasy-yaml-provider-3.6.1-7.SP7_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-undertow-2.0.26-2.SP3_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-7.2.5-4.GA_redhat_00002.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-elytron-1.6.5-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-elytron-tool-1.4.4-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-http-client-common-1.0.17-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-http-ejb-client-1.0.17-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-http-naming-client-1.0.17-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-http-transaction-client-1.0.17-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-javadocs-7.2.5-4.GA_redhat_00002.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-modules-7.2.5-4.GA_redhat_00002.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-openssl-1.0.8-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-wildfly-openssl-java-1.0.8-1.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"eap7-wildfly-openssl-linux-x86_64-1.0.8-5.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"eap7-wildfly-openssl-linux-x86_64-debuginfo-1.0.8-5.Final_redhat_00001.1.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"eap7-yasson-1.0.5-1.redhat_00001.1.el8")) flag++;

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
