#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0271 and 
# CentOS Errata and Security Advisory 2013:0271 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64692);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783");
  script_xref(name:"RHSA", value:"2013:0271");

  script_name(english:"CentOS 5 / 6 : devhelp / firefox / libproxy / xulrunner / yelp (CESA-2013:0271)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2013-0775, CVE-2013-0780, CVE-2013-0782,
CVE-2013-0783)

It was found that, after canceling a proxy server's authentication
prompt, the address bar continued to show the requested site's
address. An attacker could use this flaw to conduct phishing attacks
by tricking a user into believing they are viewing a trusted site.
(CVE-2013-0776)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Nils, Abhishek Arya, Olli Pettay,
Christoph Diehl, Gary Kwong, Jesse Ruderman, Andrew McCreight, Joe
Drew, Wayne Mery, and Michal Zalewski as the original reporters of
these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 17.0.3 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

Note that due to a Kerberos credentials change, the following
configuration steps may be required when using Firefox 17.0.3 ESR with
the Enterprise Identity Management (IPA) web interface :

https://access.redhat.com/knowledge/solutions/294303

Important: Firefox 17 is not completely backwards-compatible with all
Mozilla add-ons and Firefox plug-ins that worked with Firefox 10.0.
Firefox 17 checks compatibility on first-launch, and, depending on the
individual configuration and the installed add-ons and plug-ins, may
disable said Add-ons and plug-ins, or attempt to check for updates and
upgrade them. Add-ons and plug-ins may have to be manually updated.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 17.0.3 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8bdeb08f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1499a206"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019244.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15be145e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019245.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77355350"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?369eefed"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e3a02a3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02c2e6d3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2e28970"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0775");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-mozjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"devhelp-0.12-23.el5_9", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"devhelp-devel-0.12-23.el5_9", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-17.0.3-1.el5.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-17.0.3-1.el5_9", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-17.0.3-1.el5_9", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"yelp-2.16.0-30.el5_9", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-17.0.3-1.el6.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-0.3.0-4.el6_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-bin-0.3.0-4.el6_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-devel-0.3.0-4.el6_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-gnome-0.3.0-4.el6_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-kde-0.3.0-4.el6_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-mozjs-0.3.0-4.el6_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-python-0.3.0-4.el6_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-webkit-0.3.0-4.el6_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-17.0.3-1.el6.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-17.0.3-1.el6.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"yelp-2.28.1-17.el6_3", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / firefox / libproxy / libproxy-bin / etc");
}
