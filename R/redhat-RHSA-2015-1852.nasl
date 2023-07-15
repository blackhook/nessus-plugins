#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1852. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86241);
  script_version("2.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2015-4500", "CVE-2015-4509", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180");
  script_xref(name:"RHSA", value:"2015:1852");

  script_name(english:"RHEL 5 / 6 / 7 : thunderbird (RHSA-2015:1852)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An updated thunderbird package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Thunderbird to crash
or, potentially, execute arbitrary code with the privileges of the
user running Thunderbird. (CVE-2015-4500, CVE-2015-4509,
CVE-2015-4517, CVE-2015-4521, CVE-2015-4522, CVE-2015-7174,
CVE-2015-7175, CVE-2015-7176, CVE-2015-7177, CVE-2015-7180)

Two information leak flaws were found in the processing of malformed
web content. A web page containing malicious content could cause
Thunderbird to disclose sensitive information or, in certain cases,
crash. (CVE-2015-4519, CVE-2015-4520)

Note: All of the above issues cannot be exploited by a specially
crafted HTML mail message because JavaScript is disabled by default
for mail messages. However, they could be exploited in other ways in
Thunderbird (for example, by viewing the full remote content of an RSS
feed).

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Andrew Osmond, Olli Pettay, Andrew
Sutherland, Christian Holler, David Major, Andrew McCreight, Cameron
McCormack, Ronald Crane, Mario Gomes, and Ehsan Akhgari as the
original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Thunderbird 38.3.0 You can find a link to the
Mozilla advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 38.3.0, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # https://www.mozilla.org/en-US/security/known-vulnerabilities/thunderbird/#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3138c54"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:1852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-4500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-4509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-4520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-4521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-4522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-4517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-4519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7175"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1852";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"thunderbird-38.3.0-1.el5_11", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"thunderbird-38.3.0-1.el5_11", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"thunderbird-debuginfo-38.3.0-1.el5_11", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"thunderbird-debuginfo-38.3.0-1.el5_11", allowmaj:TRUE)) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-38.3.0-1.el6_7", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-38.3.0-1.el6_7", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-38.3.0-1.el6_7", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-debuginfo-38.3.0-1.el6_7", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-debuginfo-38.3.0-1.el6_7", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-debuginfo-38.3.0-1.el6_7", allowmaj:TRUE)) flag++;


  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"thunderbird-38.3.0-1.el7_1", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"thunderbird-debuginfo-38.3.0-1.el7_1", allowmaj:TRUE)) flag++;


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
