#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0449. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73782);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_xref(name:"RHSA", value:"2014:0449");

  script_name(english:"RHEL 5 / 6 : thunderbird (RHSA-2014:0449)");
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
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Thunderbird to crash
or, potentially, execute arbitrary code with the privileges of the
user running Thunderbird. (CVE-2014-1518, CVE-2014-1524,
CVE-2014-1529, CVE-2014-1531)

A use-after-free flaw was found in the way Thunderbird resolved hosts
in certain circumstances. An attacker could use this flaw to crash
Thunderbird or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2014-1532)

An out-of-bounds read flaw was found in the way Thunderbird decoded
JPEG images. Loading an email or a web page containing a specially
crafted JPEG image could cause Thunderbird to crash. (CVE-2014-1523)

A flaw was found in the way Thunderbird handled browser navigations
through history. An attacker could possibly use this flaw to cause the
address bar of the browser to display a web page name while loading
content from an entirely different web page, which could allow for
cross-site scripting (XSS) attacks. (CVE-2014-1530)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Bobby Holley, Carsten Book, Christoph
Diehl, Gary Kwong, Jan de Mooij, Jesse Ruderman, Nathan Froyd,
Christian Holler, Abhishek Arya, Mariusz Mlynski, moz_bug_r_a4, Nils,
Tyson Smith and Jesse Schwartzentrube as the original reporters of
these issues.

Note: All of the above issues cannot be exploited by a specially
crafted HTML mail message as JavaScript is disabled by default for
mail messages. They could be exploited another way in Thunderbird, for
example, when viewing the full remote content of an RSS feed.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Thunderbird 24.5.0. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 24.5.0, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # https://www.mozilla.org/security/known-vulnerabilities/thunderbird.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?333aa168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1529"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2014:0449";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"thunderbird-24.5.0-1.el5_10", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"thunderbird-24.5.0-1.el5_10", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"thunderbird-debuginfo-24.5.0-1.el5_10", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"thunderbird-debuginfo-24.5.0-1.el5_10", allowmaj:TRUE)) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-24.5.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-24.5.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-24.5.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-debuginfo-24.5.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-debuginfo-24.5.0-1.el6_5", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-debuginfo-24.5.0-1.el6_5", allowmaj:TRUE)) flag++;


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
