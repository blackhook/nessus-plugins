#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2054. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112247);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2015-3183", "CVE-2016-3110", "CVE-2016-4459");
  script_xref(name:"RHSA", value:"2016:2054");

  script_name(english:"RHEL 7 : JBoss EAP (RHSA-2016:2054)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that provide Red Hat JBoss Enterprise Application
Platform 6.4.10 natives, fix several bugs, and add various
enhancements are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

This release includes bug fixes and enhancements, as well as a new
release of OpenSSL. For further information, see the knowledge base
article linked to in the References section. All users of Red Hat
JBoss Enterprise Application Platform 6.4 on Red Hat Enterprise Linux
7 are advised to upgrade to these updated packages. The JBoss server
process must be restarted for the update to take effect.

Security Fix(es) :

* Multiple flaws were found in the way httpd parsed HTTP requests and
responses using chunked transfer encoding. A remote attacker could use
these flaws to create a specially crafted request, which httpd would
decode differently from an HTTP proxy software in front of it,
possibly leading to HTTP request smuggling attacks. (CVE-2015-3183)

* It was discovered that it is possible to remotely Segfault Apache
http server with a specially crafted string sent to the mod_cluster
via service messages (MCMP). (CVE-2016-3110)

* It was discovered that specifying configuration with a JVMRoute path
longer than 80 characters will cause segmentation fault leading to a
server crash. (CVE-2016-4459)

Red Hat would like to thank Michal Karm Babacek for reporting
CVE-2016-3110. The CVE-2016-4459 issue was discovered by Robert Bost
(Red Hat)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2688611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/solutions/222023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-US/"
  );
  # https://access.redhat.com/jbossnetwork/restricted/listSoftware.html?product
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?651b7563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-3183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4459"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-jbossweb-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/13");
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
  rhsa = "RHSA-2016:2054";
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

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"hornetq-native-2.3.25-4.SP11_redhat_1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"hornetq-native-debuginfo-2.3.25-4.SP11_redhat_1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-2.2.26-56.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-debuginfo-2.2.26-56.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-devel-2.2.26-56.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-manual-2.2.26-56.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd22-tools-2.2.26-56.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbcs-httpd24-1-3.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-1.0.2h-4.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2h-4.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-devel-1.0.2h-4.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-libs-1.0.2h-4.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-perl-1.0.2h-4.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-static-1.0.2h-4.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbcs-httpd24-runtime-1-3.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbossas-hornetq-native-2.3.25-4.SP11_redhat_1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbossas-jbossweb-native-1.1.34-5.redhat_1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_cluster-native-1.2.13-3.Final_redhat_2.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_cluster-native-debuginfo-1.2.13-3.Final_redhat_2.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_jk-ap22-1.2.41-2.redhat_4.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_jk-debuginfo-1.2.41-2.redhat_4.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_ldap22-2.2.26-56.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_ssl22-2.2.26-56.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tomcat-native-1.1.34-5.redhat_1.ep6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tomcat-native-debuginfo-1.1.34-5.redhat_1.ep6.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hornetq-native / hornetq-native-debuginfo / httpd22 / etc");
  }
}
