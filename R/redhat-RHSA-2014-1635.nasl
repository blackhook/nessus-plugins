#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1635. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78458);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-1574", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1581", "CVE-2014-1583");
  script_xref(name:"RHSA", value:"2014:1635");

  script_name(english:"RHEL 5 / 6 / 7 : firefox (RHSA-2014:1635)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2014-1574, CVE-2014-1578, CVE-2014-1581,
CVE-2014-1576, CVE-2014-1577)

A flaw was found in the Alarm API, which allows applications to
schedule actions to be run in the future. A malicious web application
could use this flaw to bypass cross-origin restrictions.
(CVE-2014-1583)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Bobby Holley, Christian Holler, David
Bolter, Byron Campen Jon Coppeard, Atte Kettunen, Holger Fuhrmannek,
Abhishek Arya, regenrecht, and Boris Zbarsky as the original reporters
of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 31.2.0 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 31.2.0 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # https://www.mozilla.org/security/known-vulnerabilities/firefoxESR.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1436f2f7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:1635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1578"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");
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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1635";
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
  if (rpm_check(release:"RHEL5", reference:"firefox-31.2.0-3.el5_11", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", reference:"firefox-debuginfo-31.2.0-3.el5_11", allowmaj:TRUE)) flag++;


  if (rpm_check(release:"RHEL6", reference:"firefox-31.2.0-3.el6_6", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", reference:"firefox-debuginfo-31.2.0-3.el6_6", allowmaj:TRUE)) flag++;


  if (rpm_check(release:"RHEL7", reference:"firefox-31.2.0-3.el7_0", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL7", reference:"firefox-debuginfo-31.2.0-3.el7_0", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL7", reference:"xulrunner-31.2.0-1.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xulrunner-debuginfo-31.2.0-1.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xulrunner-devel-31.2.0-1.el7_0")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo / xulrunner / xulrunner-debuginfo / etc");
  }
}
