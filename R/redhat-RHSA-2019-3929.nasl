#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3929. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131214);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/22");

  script_cve_id(
    "CVE-2018-5407",
    "CVE-2019-0199",
    "CVE-2019-0221",
    "CVE-2019-0232",
    "CVE-2019-1559",
    "CVE-2019-10072"
  );
  script_xref(name:"RHSA", value:"2019:3929");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 6 / 7 / 8 : JBoss Web Server (RHSA-2019:3929)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated Red Hat JBoss Web Server 5.2.0 packages are now available for
Red Hat Enterprise Linux 6, Red Hat Enterprise Linux 7, and Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Web Server is a fully integrated and certified set of
components for hosting Java web applications. It is comprised of the
Apache Tomcat Servlet container, JBoss HTTP Connector (mod_cluster),
the PicketLink Vault extension for Apache Tomcat, and the Tomcat
Native library.

This release of Red Hat JBoss Web Server 5.2 serves as a replacement
for Red Hat JBoss Web Server 5.1, and includes bug fixes,
enhancements, and component upgrades, which are documented in the
Release Notes, linked to in the References.

Security Fix(es) :

* openssl: Side-channel vulnerability on SMT/Hyper-Threading
architectures (PortSmash) (CVE-2018-5407)

* openssl: 0-byte record padding oracle (CVE-2019-1559)

* tomcat: HTTP/2 connection window exhaustion on write, incomplete fix
of CVE-2019-0199 (CVE-2019-10072)

* tomcat: XSS in SSI printenv (CVE-2019-0221)

* tomcat: Apache Tomcat HTTP/2 DoS (CVE-2019-0199)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_web_server/5.2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfd5659a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3929");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-5407");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-0199");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-0221");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-0232");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-1559");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-10072");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0232");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(6|7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x / 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3929";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"jws5-") || rpm_exists(release:"RHEL7", rpm:"jws5-") || rpm_exists(release:"RHEL8", rpm:"jws5-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss Web Server");

  if (rpm_check(release:"RHEL6", reference:"jws5-ecj-4.12.0-1.redhat_1.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-javapackages-tools-3.4.1-5.15.11.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-jboss-logging-3.3.2-1.Final_redhat_00001.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-mod_cluster-1.4.1-1.Final_redhat_00001.2.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-mod_cluster-tomcat-1.4.1-1.Final_redhat_00001.2.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-python-javapackages-3.4.1-5.15.11.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-9.0.21-10.redhat_4.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-admin-webapps-9.0.21-10.redhat_4.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-docs-webapp-9.0.21-10.redhat_4.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-el-3.0-api-9.0.21-10.redhat_4.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-javadoc-9.0.21-10.redhat_4.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-jsp-2.3-api-9.0.21-10.redhat_4.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-lib-9.0.21-10.redhat_4.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jws5-tomcat-native-1.2.21-34.redhat_34.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jws5-tomcat-native-1.2.21-34.redhat_34.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jws5-tomcat-native-debuginfo-1.2.21-34.redhat_34.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jws5-tomcat-native-debuginfo-1.2.21-34.redhat_34.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-selinux-9.0.21-10.redhat_4.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-servlet-4.0-api-9.0.21-10.redhat_4.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-vault-1.1.8-1.Final_redhat_1.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-vault-javadoc-1.1.8-1.Final_redhat_1.1.el6jws")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jws5-tomcat-webapps-9.0.21-10.redhat_4.1.el6jws")) flag++;

  if (rpm_check(release:"RHEL7", reference:"jws5-ecj-4.12.0-1.redhat_1.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-javapackages-tools-3.4.1-5.15.11.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-jboss-logging-3.3.2-1.Final_redhat_00001.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-mod_cluster-1.4.1-1.Final_redhat_00001.2.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-mod_cluster-tomcat-1.4.1-1.Final_redhat_00001.2.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-python-javapackages-3.4.1-5.15.11.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-9.0.21-10.redhat_4.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-admin-webapps-9.0.21-10.redhat_4.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-docs-webapp-9.0.21-10.redhat_4.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-el-3.0-api-9.0.21-10.redhat_4.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-javadoc-9.0.21-10.redhat_4.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-jsp-2.3-api-9.0.21-10.redhat_4.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-lib-9.0.21-10.redhat_4.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jws5-tomcat-native-1.2.21-34.redhat_34.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jws5-tomcat-native-debuginfo-1.2.21-34.redhat_34.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-selinux-9.0.21-10.redhat_4.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-servlet-4.0-api-9.0.21-10.redhat_4.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-vault-1.1.8-1.Final_redhat_1.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-vault-javadoc-1.1.8-1.Final_redhat_1.1.el7jws")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jws5-tomcat-webapps-9.0.21-10.redhat_4.1.el7jws")) flag++;

  if (rpm_check(release:"RHEL8", reference:"jws5-ecj-4.12.0-1.redhat_1.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-javapackages-tools-3.4.1-5.15.11.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-jboss-logging-3.3.2-1.Final_redhat_00001.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-mod_cluster-1.4.1-1.Final_redhat_00001.2.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-mod_cluster-tomcat-1.4.1-1.Final_redhat_00001.2.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-python-javapackages-3.4.1-5.15.11.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-9.0.21-10.redhat_4.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-admin-webapps-9.0.21-10.redhat_4.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-docs-webapp-9.0.21-10.redhat_4.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-el-3.0-api-9.0.21-10.redhat_4.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-javadoc-9.0.21-10.redhat_4.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-jsp-2.3-api-9.0.21-10.redhat_4.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-lib-9.0.21-10.redhat_4.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"jws5-tomcat-native-1.2.21-34.redhat_34.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"jws5-tomcat-native-debuginfo-1.2.21-34.redhat_34.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-selinux-9.0.21-10.redhat_4.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-servlet-4.0-api-9.0.21-10.redhat_4.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-vault-1.1.8-1.Final_redhat_1.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-vault-javadoc-1.1.8-1.Final_redhat_1.1.el8jws")) flag++;
  if (rpm_check(release:"RHEL8", reference:"jws5-tomcat-webapps-9.0.21-10.redhat_4.1.el8jws")) flag++;

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
