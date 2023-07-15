#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3113. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104456);
  script_version("3.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2016-2183",
    "CVE-2017-12615",
    "CVE-2017-12617",
    "CVE-2017-9788",
    "CVE-2017-9798"
  );
  script_xref(name:"RHSA", value:"2017:3113");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Web Server (RHSA-2017:3113) (Optionsbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update is now available for Red Hat JBoss Enterprise Web Server
2.1.2 for RHEL 6 and Red Hat JBoss Enterprise Web Server 2.1.2 for
RHEL 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The httpd packages provide the Apache HTTP Server, a powerful,
efficient, and extensible web server.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL)
and Transport Layer Security (TLS) protocols, as well as a
full-strength general-purpose cryptography library.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

This release provides an update to httpd, OpenSSL and Tomcat 6/7 for
Red Hat JBoss Web Server 2.1.2. The updates are documented in the
Release Notes document linked to in the References.

This release of Red Hat JBoss Web Server 2.1.2 Service Pack 2 serves
as a update for Red Hat JBoss Web Server 2, and includes bug fixes,
which are documented in the Release Notes document linked to in the
References.

Users of Red Hat JBoss Web Server 2 should upgrade to these updated
packages, which resolve several security issues.

Security Fix(es) :

* It was discovered that the httpd's mod_auth_digest module did not
properly initialize memory before using it when processing certain
headers related to digest authentication. A remote attacker could
possibly use this flaw to disclose potentially sensitive information
or cause httpd child process to crash by sending specially crafted
requests to a server. (CVE-2017-9788)

* A vulnerability was discovered in Tomcat where if a servlet context
was configured with readonly=false and HTTP PUT requests were allowed,
an attacker could upload a JSP file to that context and achieve code
execution. (CVE-2017-12615)

* A vulnerability was discovered in Tomcat where if a servlet context
was configured with readonly=false and HTTP PUT requests were allowed,
an attacker could upload a JSP file to that context and achieve code
execution. (CVE-2017-12617)

* A flaw was found in the way the DES/3DES cipher was used as part of
the TLS /SSL protocol. A man-in-the-middle attacker could use this
flaw to recover some plaintext data by capturing large amounts of
encrypted traffic between TLS/SSL server and client if the
communication used a DES/3DES based ciphersuite. (CVE-2016-2183)

* A use-after-free flaw was found in the way httpd handled invalid and
previously unregistered HTTP methods specified in the Limit directive
used in an .htaccess file. A remote attacker could possibly use this
flaw to disclose portions of the server memory, or cause httpd child
process to crash. (CVE-2017-9798)

Red Hat would like to thank OpenVPN for reporting CVE-2016-2183 and
Hanno Bock for reporting CVE-2017-9798. Upstream acknowledges
Karthikeyan Bhargavan (Inria) and Gaetan Leurent (Inria) as the
original reporters of CVE-2016-2183.

Bug Fix(es) :

* Corruption in nodestatsmem in multiple core dumps but in different
functions of each core dump. (BZ#1338640)

* mod_cluster segfaults in process_info() due to wrongly generated
assembler instruction movslq (BZ#1448709)

* CRL checking of very large CRLs fails with OpenSSL 1.0.2
(BZ#1493075)");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/3227901");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:3113");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-2183");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-12615");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-12617");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-9788");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-9798");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12617");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-9788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-maven-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-maven-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2017:3113";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"jws-2") || rpm_exists(release:"RHEL7", rpm:"jws-2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss Web Server");

  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-debuginfo-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-debuginfo-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-devel-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-devel-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-manual-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-manual-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-tools-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-tools-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-devel-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-devel-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-libs-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-libs-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-perl-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-perl-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-static-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-static-1.0.2h-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_cluster-native-1.2.13-9.Final_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_cluster-native-1.2.13-9.Final_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_cluster-native-debuginfo-1.2.13-9.Final_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_cluster-native-debuginfo-1.2.13-9.Final_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_ldap-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ldap-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_ssl-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ssl-2.2.26-57.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-admin-webapps-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-docs-webapp-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-el-2.1-api-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-javadoc-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-jsp-2.1-api-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-lib-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-log4j-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-maven-devel-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-servlet-2.5-api-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-webapps-6.0.41-19_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-admin-webapps-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-docs-webapp-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-el-2.2-api-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-javadoc-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-jsp-2.2-api-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-lib-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-log4j-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-maven-devel-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-servlet-3.0-api-7.0.54-28_patch_05.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-webapps-7.0.54-28_patch_05.ep6.el6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-2.2.26-58.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-debuginfo-2.2.26-58.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-devel-2.2.26-58.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-manual-2.2.26-58.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-tools-2.2.26-58.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-1.0.2h-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2h-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-devel-1.0.2h-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-libs-1.0.2h-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-perl-1.0.2h-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-static-1.0.2h-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_cluster-native-1.2.13-9.Final_redhat_2.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_cluster-native-debuginfo-1.2.13-9.Final_redhat_2.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_ldap22-2.2.26-58.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_ssl22-2.2.26-58.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-admin-webapps-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-docs-webapp-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-el-2.1-api-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-javadoc-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-jsp-2.1-api-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-lib-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-log4j-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-maven-devel-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-servlet-2.5-api-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat6-webapps-6.0.41-19_patch_04.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-admin-webapps-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-docs-webapp-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-el-2.2-api-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-javadoc-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-jsp-2.2-api-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-lib-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-log4j-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-maven-devel-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-servlet-3.0-api-7.0.54-28_patch_05.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-webapps-7.0.54-28_patch_05.ep6.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
  }
}
