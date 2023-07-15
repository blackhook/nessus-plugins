#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0264. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81505);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2014-3065", "CVE-2014-3068", "CVE-2014-3566", "CVE-2014-4209", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4227", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4265", "CVE-2014-4288", "CVE-2014-6457", "CVE-2014-6458", "CVE-2014-6492", "CVE-2014-6493", "CVE-2014-6502", "CVE-2014-6503", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6515", "CVE-2014-6531", "CVE-2014-6532", "CVE-2014-6558", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-8891", "CVE-2014-8892", "CVE-2015-0395", "CVE-2015-0403", "CVE-2015-0406", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412");
  script_bugtraq_id(73258, 73259);
  script_xref(name:"RHSA", value:"2015:0264");

  script_name(english:"RHEL 5 / 6 : Red Hat Satellite IBM Java Runtime (RHSA-2015:0264) (POODLE)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated java-1.6.0-ibm packages that fix several security issues are
now available for Red Hat Satellite 5.6.

Red Hat Product Security has rated this update as having Low security
impact. Common Vulnerability Scoring System (CVSS) base scores, which
give detailed severity ratings, are available for each vulnerability
from the CVE links in the References section.

This update corrects several security vulnerabilities in the IBM Java
Runtime Environment shipped as part of Red Hat Satellite 5.6. In a
typical operating environment, these are of low security risk as the
runtime is not used on untrusted applets.

Several flaws were fixed in the IBM Java 2 Runtime Environment.
(CVE-2014-3065, CVE-2014-3068, CVE-2014-3566, CVE-2014-4209,
CVE-2014-4218, CVE-2014-4219, CVE-2014-4227, CVE-2014-4244,
CVE-2014-4252, CVE-2014-4262, CVE-2014-4263, CVE-2014-4265,
CVE-2014-4288, CVE-2014-6457, CVE-2014-6458, CVE-2014-6492,
CVE-2014-6493, CVE-2014-6502, CVE-2014-6503, CVE-2014-6506,
CVE-2014-6511, CVE-2014-6512, CVE-2014-6515, CVE-2014-6531,
CVE-2014-6532, CVE-2014-6558, CVE-2014-6585, CVE-2014-6587,
CVE-2014-6591, CVE-2014-6593, CVE-2014-8891, CVE-2014-8892,
CVE-2015-0395, CVE-2015-0403, CVE-2015-0406, CVE-2015-0407,
CVE-2015-0408, CVE-2015-0410, CVE-2015-0412)

The CVE-2014-4262 and CVE-2014-6512 issues were discovered by Florian
Weimer of Red Hat Product Security.

Users of Red Hat Satellite 5.6 are advised to upgrade to these updated
packages, which contain the IBM Java SE 6 SR16-FP3 release. For this
update to take effect, Red Hat Satellite must be restarted
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
    value:"https://access.redhat.com/errata/RHSA-2015:0264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8891"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected java-1.6.0-ibm and / or java-1.6.0-ibm-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2015:0264";
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
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.16.3-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.16.3-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.6.0-ibm-devel-1.6.0.16.3-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-devel-1.6.0.16.3-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.16.3-1jpp.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.16.3-1jpp.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-devel-1.6.0.16.3-1jpp.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-devel-1.6.0.16.3-1jpp.1.el6")) flag++;

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
