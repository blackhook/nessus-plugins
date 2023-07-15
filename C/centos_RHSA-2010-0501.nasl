#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0501 and 
# CentOS Errata and Security Advisory 2010:0501 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47129);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-5913", "CVE-2009-5017", "CVE-2010-0182", "CVE-2010-0183", "CVE-2010-1028", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-3171");
  script_xref(name:"RHSA", value:"2010:0501");

  script_name(english:"CentOS 5 : firefox (CESA-2010:0501)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that address several security issues, fix
bugs, add numerous enhancements, and upgrade Firefox to version 3.6.4,
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

[Updated 25 June 2010] The original packages distributed with this
erratum had a bug which could cause unintended dependencies to be
installed when upgrading. We have updated the packages to correct this
bug.

Mozilla Firefox is an open source web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-1121, CVE-2010-1200, CVE-2010-1202,
CVE-2010-1203)

A flaw was found in the way browser plug-ins interact. It was possible
for a plug-in to reference the freed memory from a different plug-in,
resulting in the execution of arbitrary code with the privileges of
the user running Firefox. (CVE-2010-1198)

Several integer overflow flaws were found in the processing of
malformed web content. A web page containing malicious content could
cause Firefox to crash or, potentially, execute arbitrary code with
the privileges of the user running Firefox. (CVE-2010-1196,
CVE-2010-1199)

A focus stealing flaw was found in the way Firefox handled focus
changes. A malicious website could use this flaw to steal sensitive
data from a user, such as usernames and passwords. (CVE-2010-1125)

A flaw was found in the way Firefox handled the 'Content-Disposition:
attachment' HTTP header when the 'Content-Type: multipart' HTTP header
was also present. A website that allows arbitrary uploads and relies
on the 'Content-Disposition: attachment' HTTP header to prevent
content from being displayed inline, could be used by an attacker to
serve malicious content to users. (CVE-2010-1197)

A flaw was found in the Firefox Math.random() function. This function
could be used to identify a browsing session and track a user across
different websites. (CVE-2008-5913)

A flaw was found in the Firefox XML document loading security checks.
Certain security checks were not being called when an XML document was
loaded. This could possibly be leveraged later by an attacker to load
certain resources that violate the security policies of the browser or
its add-ons. Note that this issue cannot be exploited by only loading
an XML document. (CVE-2010-0182)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.4. You can find a link to the
Mozilla advisories in the References section of this erratum.

This erratum upgrades Firefox from version 3.0.19 to version 3.6.4.
Due to the requirements of Firefox 3.6.4, this erratum also provides a
number of other updated packages, including esc, totem, and yelp.

This erratum also contains multiple bug fixes and numerous
enhancements. Space precludes documenting these changes in this
advisory. For details concerning these changes, refer to the Firefox
Release Notes links in the References section of this erratum.

Important: Firefox 3.6.4 is not completely backwards-compatible with
all Mozilla Add-ons and Firefox plug-ins that worked with Firefox
3.0.19. Firefox 3.6 checks compatibility on first-launch, and,
depending on the individual configuration and the installed Add-ons
and plug-ins, may disable said Add-ons and plug-ins, or attempt to
check for updates and upgrade them. Add-ons and plug-ins may have to
be manually updated.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.4. After installing the update, Firefox
must be restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-June/016745.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1df5736d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-June/016746.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5b26d40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:esc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-gtkspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-libegg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-mozplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"devhelp-0.12-20.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"devhelp-devel-0.12-20.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"esc-1.1.0-12.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-3.6.4-8.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnome-python2-extras-2.14.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnome-python2-gtkhtml2-2.14.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnome-python2-gtkmozembed-2.14.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnome-python2-gtkspell-2.14.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnome-python2-libegg-2.14.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"totem-2.16.7-7.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"totem-devel-2.16.7-7.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"totem-mozplugin-2.16.7-7.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.4-9.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.4-9.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"yelp-2.16.0-26.el5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / esc / firefox / gnome-python2-extras / etc");
}
