#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1773. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119378);
  script_version("1.7");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2014-3577", "CVE-2015-7501", "CVE-2016-0788", "CVE-2016-0789", "CVE-2016-0790", "CVE-2016-0791", "CVE-2016-0792", "CVE-2016-3721", "CVE-2016-3722", "CVE-2016-3723", "CVE-2016-3724", "CVE-2016-3725", "CVE-2016-3726", "CVE-2016-3727");
  script_xref(name:"RHSA", value:"2016:1773");

  script_name(english:"RHEL 6 : Red Hat OpenShift Enterprise 2.2.10 (RHSA-2016:1773)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat OpenShift Enterprise 2.2.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

* The Jenkins continuous integration server has been updated to
upstream version 1.651.2 LTS that addresses a large number of security
issues, including open redirects, a potential denial of service,
unsafe handling of user provided environment variables and several
instances of sensitive information disclosure. (CVE-2014-3577,
CVE-2016-0788, CVE-2016-0789, CVE-2016-0790, CVE-2016-0791,
CVE-2016-0792, CVE-2016-3721, CVE-2016-3722, CVE-2016-3723,
CVE-2016-3724, CVE-2016-3725, CVE-2016-3726, CVE-2016-3727,
CVE-2015-7501)

Space precludes documenting all of the bug fixes and enhancements in
this advisory. See the OpenShift Enterprise Technical Notes, which
will be updated shortly for release 2.2.10, for details about these
changes :

https://access.redhat.com/documentation/en-US/OpenShift_Enterprise/2/
html-single/Technical_Notes/index.html

All OpenShift Enterprise 2 users are advised to upgrade to these
updated packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-0788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-0789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-0790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-0791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-0792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3727"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Jenkins XStream Groovy classpath Deserialization Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:activemq-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcgroup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcgroup-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-diy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbosseap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbossews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jenkins-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-msg-node-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-admin-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-haproxy-sni-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-msg-broker-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-routing-daemon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1773";
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

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.7.2.7-5.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ImageMagick-devel-6.7.2.7-5.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ImageMagick-doc-6.7.2.7-5.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ImageMagick-perl-6.7.2.7-5.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"activemq-5.9.0-6.redhat.611463.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"activemq-client-5.9.0-6.redhat.611463.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jenkins-1.651.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libcgroup-debuginfo-0.40.rc1-18.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libcgroup-pam-0.40.rc1-18.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-1.16.3.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-util-1.37.6.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-cron-1.25.4.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-diy-1.26.2.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-haproxy-1.31.6.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jbosseap-2.27.4.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jbossews-1.35.5.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jenkins-1.29.2.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jenkins-client-1.26.1.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-mongodb-1.26.2.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-mysql-1.31.3.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-nodejs-1.33.1.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-perl-1.30.2.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-php-1.35.4.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-python-1.34.3.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-ruby-1.32.2.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-msg-node-mcollective-1.30.2.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-node-proxy-1.26.3.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-node-util-1.38.7.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhc-1.38.7.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-admin-console-1.28.2.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-controller-1.38.6.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-frontend-haproxy-sni-proxy-0.5.2.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-msg-broker-mcollective-1.36.2.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-node-1.38.6.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-routing-daemon-0.26.6.1-1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick-debuginfo / ImageMagick-devel / ImageMagick-doc / etc");
  }
}
