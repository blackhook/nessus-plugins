#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0079 and 
# CentOS Errata and Security Advisory 2012:0079 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57777);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0444", "CVE-2012-0449");
  script_bugtraq_id(51753, 51754, 51755, 51756);
  script_xref(name:"RHSA", value:"2012:0079");

  script_name(english:"CentOS 4 / 5 / 6 : firefox (CESA-2012:0079)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A use-after-free flaw was found in the way Firefox removed
nsDOMAttribute child nodes. In certain circumstances, due to the
premature notification of AttributeChildRemoved, a malicious script
could possibly use this flaw to cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2011-3659)

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2012-0442)

A flaw was found in the way Firefox parsed Ogg Vorbis media files. A
web page containing a malicious Ogg Vorbis media file could cause
Firefox to crash or, potentially, execute arbitrary code with the
privileges of the user running Firefox. (CVE-2012-0444)

A flaw was found in the way Firefox parsed certain Scalable Vector
Graphics (SVG) image files that contained eXtensible Style Sheet
Language Transformations (XSLT). A web page containing a malicious SVG
image file could cause Firefox to crash or, potentially, execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2012-0449)

The same-origin policy in Firefox treated http://example.com and
http://[example.com] as interchangeable. A malicious script could
possibly use this flaw to gain access to sensitive information (such
as a client's IP and user e-mail address, or httpOnly cookies) that
may be included in HTTP proxy error replies, generated in response to
invalid URLs using square brackets. (CVE-2011-3670)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.26. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.26, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-February/018407.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fa2cbb6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-January/018404.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99054853"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-January/018405.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?902b2dfa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3659");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.26-2.el4.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.26-2.el4.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.6.26-1.el5.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.26-1.el5_7", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.26-1.el5_7", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-3.6.26-1.el6.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-1.9.2.26-1.el6.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-1.9.2.26-1.el6.centos", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / xulrunner / xulrunner-devel");
}
