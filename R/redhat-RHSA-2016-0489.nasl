#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0489. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119368);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2015-5254",
    "CVE-2015-5317",
    "CVE-2015-5318",
    "CVE-2015-5319",
    "CVE-2015-5320",
    "CVE-2015-5321",
    "CVE-2015-5322",
    "CVE-2015-5323",
    "CVE-2015-5324",
    "CVE-2015-5325",
    "CVE-2015-5326",
    "CVE-2015-7537",
    "CVE-2015-7538",
    "CVE-2015-7539",
    "CVE-2015-8103"
  );
  script_xref(name:"RHSA", value:"2016:0489");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"RHEL 6 : Red Hat OpenShift Enterprise 2.2.9 (RHSA-2016:0489)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Red Hat OpenShift Enterprise release 2.2.9, which fixes several
security issues, several bugs, and introduces feature enhancements, is
now available.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

The following security issue is addressed with this release :

It was found that ActiveMQ did not safely handle user-supplied data
when deserializing objects. A remote attacker could use this flaw to
execute arbitrary code with the permissions of the ActiveMQ
application. (CVE-2015-5254)

An update for Jenkins Continuous Integration Server that addresses a
large number of security issues including XSS, CSRF, information
disclosure and code execution have been addressed as well.
(CVE-2015-5317, CVE-2015-5318, CVE-2015-5319, CVE-2015-5320,
CVE-2015-5321, CVE-2015-5322, CVE-2015-5323, CVE-2015-5324,
CVE-2015-5325, CVE-2015-5326, CVE-2015-7537, CVE-2015-7538,
CVE-2015-7539, CVE-2015-8103)

Space precludes documenting all of the bug fixes in this advisory. See
the OpenShift Enterprise Technical Notes, which will be updated
shortly for release 2.2.9, for details about these changes :

https://access.redhat.com/documentation/en-US/OpenShift_Enterprise/2/
html-single/Technical_Notes/index.html

All OpenShift Enterprise 2 users are advised to upgrade to these
updated packages.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:0489");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7538");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7539");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5318");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7537");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5320");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5317");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8103");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5324");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5325");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5254");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5326");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5321");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5319");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5323");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5322");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7539");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-5254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenNMS Java Object Unserialization Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:activemq-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-yum-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-msg-node-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-apache-vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2016:0489";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"openshift-origin"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenShift");

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"activemq-client-5.9.0-6.redhat.611454.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jenkins-1.625.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-release-2.2.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-upgrade-node-2.2.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-yum-validator-2.2.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-cron-1.25.2.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-haproxy-1.31.5.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-mysql-1.31.2.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-php-1.35.3.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-python-1.34.2.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-msg-node-mcollective-1.30.2.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-node-proxy-1.26.2.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-node-util-1.38.6.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-bcmath-5.3.3-46.el6_7.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-debuginfo-5.3.3-46.el6_7.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-devel-5.3.3-46.el6_7.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-fpm-5.3.3-46.el6_7.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-imap-5.3.3-46.el6_7.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-intl-5.3.3-46.el6_7.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mbstring-5.3.3-46.el6_7.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-process-5.3.3-46.el6_7.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-common-1.29.5.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-frontend-apache-vhost-0.13.2.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-node-1.38.5.3-1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "activemq-client / jenkins / openshift-enterprise-release / etc");
  }
}
