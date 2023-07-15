#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3477. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105369);
  script_version("3.7");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2017-12613", "CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7679", "CVE-2017-9798");
  script_xref(name:"RHSA", value:"2017:3477");

  script_name(english:"RHEL 6 : Red Hat JBoss Core Services Apache HTTP Server 2.4.23 (RHSA-2017:3477) (Optionsbleed)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for JBoss Core Services on RHEL 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Core Services is a set of supplementary software for Red
Hat JBoss middleware products. This software, such as Apache HTTP
Server, is common to multiple JBoss middleware products, and is
packaged under Red Hat JBoss Core Services to allow for faster
distribution of updates, and for a more consistent update experience.

This release of Red Hat JBoss Core Services Apache HTTP Server 2.4.23
Service Pack 3 serves as an update to Red Hat JBoss Core Services
Apache HTTP Server 2.4.23 Service Pack 2, and includes bug fixes,
which are documented in the Release Notes document linked to in the
References.

Security Fix(es) :

* An out-of-bounds array dereference was found in apr_time_exp_get().
An attacker could abuse an unvalidated usage of this function to cause
a denial of service or potentially lead to data leak. (CVE-2017-12613)

* It was discovered that the use of httpd's ap_get_basic_auth_pw() API
function outside of the authentication phase could lead to
authentication bypass. A remote attacker could possibly use this flaw
to bypass required authentication if the API was used incorrectly by
one of the modules used by httpd. (CVE-2017-3167)

* A NULL pointer dereference flaw was found in the httpd's mod_ssl
module. A remote attacker could use this flaw to cause an httpd child
process to crash if another module used by httpd called a certain API
function during the processing of an HTTPS request. (CVE-2017-3169)

* A buffer over-read flaw was found in the httpd's mod_mime module. A
user permitted to modify httpd's MIME configuration could use this
flaw to cause httpd child process to crash. (CVE-2017-7679)

* A use-after-free flaw was found in the way httpd handled invalid and
previously unregistered HTTP methods specified in the Limit directive
used in an .htaccess file. A remote attacker could possibly use this
flaw to disclose portions of the server memory, or cause httpd child
process to crash. (CVE-2017-9798)

Red Hat would like to thank Hanno Bock for reporting CVE-2017-9798."
  );
  # https://access.redhat.com/documentation/en/red-hat-jboss-core-services/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75d9eb14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:3477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12613"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_bmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_bmx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_cluster-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2017:3477";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-debuginfo-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-debuginfo-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-devel-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-devel-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-libs-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-libs-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbcs-httpd24-httpd-manual-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-selinux-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-selinux-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-tools-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-tools-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_bmx-0.9.6-15.GA.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_bmx-0.9.6-15.GA.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_bmx-debuginfo-0.9.6-15.GA.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_bmx-debuginfo-0.9.6-15.GA.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_cluster-native-1.3.8-1.Final_redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_cluster-native-1.3.8-1.Final_redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_cluster-native-debuginfo-1.3.8-1.Final_redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_cluster-native-debuginfo-1.3.8-1.Final_redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_ldap-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_ldap-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_proxy_html-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_proxy_html-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_session-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_session-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_ssl-2.4.23-125.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_ssl-2.4.23-125.jbcs.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbcs-httpd24-httpd / jbcs-httpd24-httpd-debuginfo / etc");
  }
}
