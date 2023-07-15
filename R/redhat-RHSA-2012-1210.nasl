#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1210. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61704);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1970", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3972", "CVE-2012-3976", "CVE-2012-3978", "CVE-2012-3980");
  script_xref(name:"RHSA", value:"2012:1210");

  script_name(english:"RHEL 5 / 6 : firefox (RHSA-2012:1210)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A web page containing malicious content could cause Firefox to crash
or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2012-1970, CVE-2012-1972, CVE-2012-1973,
CVE-2012-1974, CVE-2012-1975, CVE-2012-1976, CVE-2012-3956,
CVE-2012-3957, CVE-2012-3958, CVE-2012-3959, CVE-2012-3960,
CVE-2012-3961, CVE-2012-3962, CVE-2012-3963, CVE-2012-3964)

A web page containing a malicious Scalable Vector Graphics (SVG) image
file could cause Firefox to crash or, potentially, execute arbitrary
code with the privileges of the user running Firefox. (CVE-2012-3969,
CVE-2012-3970)

Two flaws were found in the way Firefox rendered certain images using
WebGL. A web page containing malicious content could cause Firefox to
crash or, under certain conditions, possibly execute arbitrary code
with the privileges of the user running Firefox. (CVE-2012-3967,
CVE-2012-3968)

A flaw was found in the way Firefox decoded embedded bitmap images in
Icon Format (ICO) files. A web page containing a malicious ICO file
could cause Firefox to crash or, under certain conditions, possibly
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2012-3966)

A flaw was found in the way the 'eval' command was handled by the
Firefox Web Console. Running 'eval' in the Web Console while viewing a
web page containing malicious content could possibly cause Firefox to
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2012-3980)

An out-of-bounds memory read flaw was found in the way Firefox used
the format-number feature of XSLT (Extensible Stylesheet Language
Transformations). A web page containing malicious content could
possibly cause an information leak, or cause Firefox to crash.
(CVE-2012-3972)

It was found that the SSL certificate information for a previously
visited site could be displayed in the address bar while the main
window displayed a new page. This could lead to phishing attacks as
attackers could use this flaw to trick users into believing they are
viewing a trusted site. (CVE-2012-3976)

A flaw was found in the location object implementation in Firefox.
Malicious content could use this flaw to possibly allow restricted
content to be loaded. (CVE-2012-3978)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.7 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Gary Kwong, Christian Holler, Jesse
Ruderman, John Schoenick, Vladimir Vukicevic, Daniel Holbert, Abhishek
Arya, Frederic Hoguin, miaubiz, Arthur Gerkis, Nicolas Gregoire, Mark
Poticha, moz_bug_r_a4, and Colby Russell as the original reporters of
these issues.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.7 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefoxESR.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a134523f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:1210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-1975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-1974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-1976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-1970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-1973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-1972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3976"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2012:1210";
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
  if (rpm_check(release:"RHEL5", reference:"firefox-10.0.7-1.el5_8", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", reference:"firefox-debuginfo-10.0.7-1.el5_8", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-10.0.7-2.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-debuginfo-10.0.7-2.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-devel-10.0.7-2.el5_8")) flag++;


  if (rpm_check(release:"RHEL6", reference:"firefox-10.0.7-1.el6_3", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", reference:"firefox-debuginfo-10.0.7-1.el6_3", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-10.0.7-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-debuginfo-10.0.7-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-devel-10.0.7-1.el6_3")) flag++;


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
