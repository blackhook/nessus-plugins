#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1823. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71370);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0772", "CVE-2013-5609", "CVE-2013-5612", "CVE-2013-5613", "CVE-2013-5614", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-6671", "CVE-2013-6674");
  script_xref(name:"RHSA", value:"2013:1823");

  script_name(english:"RHEL 5 / 6 : thunderbird (RHSA-2013:1823)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2013-5609, CVE-2013-5616, CVE-2013-5618,
CVE-2013-6671, CVE-2013-5613)

A flaw was found in the way Thunderbird rendered web content with
missing character encoding information. An attacker could use this
flaw to possibly bypass same-origin inheritance and perform cross
site-scripting (XSS) attacks. (CVE-2013-5612)

It was found that certain malicious web content could bypass
restrictions applied by sandboxed iframes. An attacker could combine
this flaw with other vulnerabilities to execute arbitrary code with
the privileges of the user running Thunderbird. (CVE-2013-5614)

Note: All of the above issues cannot be exploited by a specially
crafted HTML mail message as JavaScript is disabled by default for
mail messages. They could be exploited another way in Thunderbird, for
example, when viewing the full remote content of an RSS feed.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Ben Turner, Bobby Holley, Jesse
Ruderman, Christian Holler, Masato Kinugawa, Daniel Veditz, Jesse
Schwartzentruber, Nils, Tyson Smith, and Atte Kettunen as the original
reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Thunderbird 24.2.0 ESR. You can find a link to
the Mozilla advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 24.2.0 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbirdESR.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a148a6e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:1823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-6671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-6674"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2013:1823";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"thunderbird-24.2.0-2.el5_10", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"thunderbird-24.2.0-2.el5_10", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"thunderbird-debuginfo-24.2.0-2.el5_10", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"thunderbird-debuginfo-24.2.0-2.el5_10", allowmaj:TRUE)) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-24.2.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-24.2.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-24.2.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-debuginfo-24.2.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-debuginfo-24.2.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-debuginfo-24.2.0-1.el6_5", allowmaj:TRUE)) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
  }
}
