#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0310 and 
# CentOS Errata and Security Advisory 2011:0310 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52507);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062");
  script_xref(name:"RHSA", value:"2011:0310");

  script_name(english:"CentOS 4 : firefox (CESA-2011:0310)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues and one bug
are now available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A flaw was found in the way Firefox sanitized HTML content in
extensions. If an extension loaded or rendered malicious content using
the ParanoidFragmentSink class, it could fail to safely display the
content, causing Firefox to execute arbitrary JavaScript with the
privileges of the user running Firefox. (CVE-2010-1585)

A flaw was found in the way Firefox handled dialog boxes. An attacker
could use this flaw to create a malicious web page that would present
a blank dialog box that has non-functioning buttons. If a user closes
the dialog box window, it could unexpectedly grant the malicious web
page elevated privileges. (CVE-2011-0051)

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2011-0053, CVE-2011-0055, CVE-2011-0058,
CVE-2011-0062)

Several flaws were found in the way Firefox handled malformed
JavaScript. A website containing malicious JavaScript could cause
Firefox to execute that JavaScript with the privileges of the user
running Firefox. (CVE-2011-0054, CVE-2011-0056, CVE-2011-0057)

A flaw was found in the way Firefox handled malformed JPEG images. A
website containing a malicious JPEG image could cause Firefox to crash
or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2011-0061)

A flaw was found in the way Firefox handled plug-ins that perform HTTP
requests. If a plug-in performed an HTTP request, and the server sent
a 307 redirect response, the plug-in was not notified, and the HTTP
request was forwarded. The forwarded request could contain custom
headers, which could result in a Cross Site Request Forgery attack.
(CVE-2011-0059)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.14. You can find a link to the
Mozilla advisories in the References section of this erratum.

This update also fixes the following bug :

* On Red Hat Enterprise Linux 4 and 5, running the 'firefox
-setDefaultBrowser' command caused warnings such as the following :

libgnomevfs-WARNING **: Deprecated function. User modifications to the
MIME database are no longer supported.

This update disables the 'setDefaultBrowser' option. Red Hat
Enterprise Linux 4 users wishing to set a default web browser can use
Applications -> Preferences -> More Preferences -> Preferred
Applications. Red Hat Enterprise Linux 5 users can use System ->
Preferences -> Preferred Applications. (BZ#463131, BZ#665031)

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.14, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-March/017266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3154c2d5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-March/017267.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6694aab"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.14-4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.14-4.el4.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
