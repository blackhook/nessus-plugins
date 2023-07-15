#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1091. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84143);
  script_version("2.13");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2005-1080", "CVE-2015-0138", "CVE-2015-0192", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-1914", "CVE-2015-2808");
  script_xref(name:"RHSA", value:"2015:1091");

  script_name(english:"RHEL 5 / 6 : Red Hat Satellite IBM Java Runtime (RHSA-2015:1091) (Bar Mitzvah)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-ibm packages that fix several security issues are
now available for Red Hat Satellite 5.6 and 5.7.

Red Hat Product Security has rated this update as having Low security
impact. Common Vulnerability Scoring System (CVSS) base scores, which
give detailed severity ratings, are available for each vulnerability
from the CVE links in the References section.

IBM Java SE version 6 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update corrects several security vulnerabilities in the IBM Java
Runtime Environment shipped as part of Red Hat Satellite 5. In a
typical operating environment, these are of low security risk as the
runtime is not used on untrusted applets. Further information about
these flaws can be found on the IBM Java Security alerts page, listed
in the References section. (CVE-2005-1080, CVE-2015-0138,
CVE-2015-0192, CVE-2015-0458, CVE-2015-0459, CVE-2015-0469,
CVE-2015-0477, CVE-2015-0478, CVE-2015-0480, CVE-2015-0488,
CVE-2015-0491, CVE-2015-1914, CVE-2015-2808)

The CVE-2015-0478 issue was discovered by Florian Weimer of Red Hat
Product Security.

Note: With this update, the IBM JDK now disables RC4 SSL/TLS cipher
suites by default to address the CVE-2015-2808 issue. Refer to Red Hat
Bugzilla bug 1207101, linked to from the References section, for
additional details about this change.

Users of Red Hat Satellite 5.6 and 5.7 are advised to upgrade to these
updated packages, which contain the IBM Java SE 6 SR16-FP4 release.
For this update to take effect, Red Hat Satellite must be restarted
('/usr/sbin/rhn-satellite restart'), as well as all running instances
of IBM Java."
  );
  # https://www.ibm.com/developerworks/java/jdk/alerts/
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.ibm.com/javasdk/support/security-vulnerabilities/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1207101#c4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:1091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-1080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-1914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-2808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0138"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected java-1.6.0-ibm and / or java-1.6.0-ibm-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1091";
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
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.16.4-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.16.4-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.6.0-ibm-devel-1.6.0.16.4-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-devel-1.6.0.16.4-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.16.4-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.16.4-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-devel-1.6.0.16.4-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-devel-1.6.0.16.4-1jpp.1.el6_6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-ibm / java-1.6.0-ibm-devel");
  }
}
