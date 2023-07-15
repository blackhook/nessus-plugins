#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0451. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122606);
  script_version("1.5");
  script_cvs_date("Date: 2020/02/06");

  script_cve_id("CVE-2018-8014", "CVE-2018-8034");
  script_xref(name:"RHSA", value:"2019:0451");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Web Server 5.0 Service Pack 2 (RHSA-2019:0451)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat JBoss Web Server 5.0 for RHEL 6
and Red Hat JBoss Web Server 5.0 for RHEL 7.

Red Hat Product Security has rated this release as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Web Server is a fully integrated and certified set of
components for hosting Java web applications. It is comprised of the
Apache Tomcat Servlet container, JBoss HTTP Connector (mod_cluster),
the PicketLink Vault extension for Apache Tomcat, and the Tomcat
Native library.

This release of Red Hat JBoss Web Server 5.0 Service Pack 2 serves as
a replacement for Red Hat JBoss Web Server 5.0 Service Pack 1, and
includes bug fixes, which are documented in the Release Notes document
linked to in the References.

Security Fix(es) :

* tomcat: Insecure defaults in CORS filter enable
'supportsCredentials' for all origins (CVE-2018-8014)

* tomcat: host name verification missing in WebSocket client
(CVE-2018-8034)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-8014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-8034"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-ecj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-javapackages-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-mod_cluster-tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-python-javapackages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-el-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-servlet-4.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-vault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-vault-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2019:0451";
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
  if (rpm_check(release:"RHEL6", reference:"jws5-ecj-4.6.1-6.redhat_1.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-javapackages-tools-3.4.1-5.15.10.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-jboss-logging-3.3.1-5.Final_redhat_1.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-mod_cluster-1.4.0-9.Final_redhat_1.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-mod_cluster-tomcat-1.4.0-9.Final_redhat_1.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-python-javapackages-3.4.1-5.15.10.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-admin-webapps-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-docs-webapp-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-el-3.0-api-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-javadoc-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-jsp-2.3-api-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-jsvc-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-lib-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jws5-tomcat-native-1.2.17-26.redhat_26.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jws5-tomcat-native-1.2.17-26.redhat_26.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jws5-tomcat-native-debuginfo-1.2.17-26.redhat_26.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jws5-tomcat-native-debuginfo-1.2.17-26.redhat_26.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-selinux-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-servlet-4.0-api-9.0.7-17.redhat_16.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-vault-1.1.7-5.Final_redhat_2.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-vault-javadoc-1.1.7-5.Final_redhat_2.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-webapps-9.0.7-17.redhat_16.1.el6jws")) flag++;

  if (rpm_check(release:"RHEL7", reference:"jws5-ecj-4.6.1-6.redhat_1.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-javapackages-tools-3.4.1-5.15.10.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-jboss-logging-3.3.1-5.Final_redhat_1.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-mod_cluster-1.4.0-9.Final_redhat_1.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-mod_cluster-tomcat-1.4.0-9.Final_redhat_1.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-python-javapackages-3.4.1-5.15.10.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-admin-webapps-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-docs-webapp-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-el-3.0-api-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-javadoc-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-jsp-2.3-api-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-jsvc-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-lib-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jws5-tomcat-native-1.2.17-26.redhat_26.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jws5-tomcat-native-debuginfo-1.2.17-26.redhat_26.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-selinux-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-servlet-4.0-api-9.0.7-17.redhat_16.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-vault-1.1.7-5.Final_redhat_2.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-vault-javadoc-1.1.7-5.Final_redhat_2.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-webapps-9.0.7-17.redhat_16.1.el7jws")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jws5-ecj / jws5-javapackages-tools / jws5-jboss-logging / etc");
  }
}
