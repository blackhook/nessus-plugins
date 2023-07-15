#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0473 and 
# CentOS Errata and Security Advisory 2011:0473 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53600);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080");
  script_xref(name:"RHSA", value:"2011:0473");

  script_name(english:"CentOS 4 : seamonkey (CESA-2011:0473)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

SeaMonkey is an open source web browser, email and newsgroup client,
IRC chat client, and HTML editor.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could possibly lead to arbitrary
code execution with the privileges of the user running SeaMonkey.
(CVE-2011-0080)

An arbitrary memory write flaw was found in the way SeaMonkey handled
out-of-memory conditions. If all memory was consumed when a user
visited a malicious web page, it could possibly lead to arbitrary code
execution with the privileges of the user running SeaMonkey.
(CVE-2011-0078)

An integer overflow flaw was found in the way SeaMonkey handled the
HTML frameset tag. A web page with a frameset tag containing large
values for the 'rows' and 'cols' attributes could trigger this flaw,
possibly leading to arbitrary code execution with the privileges of
the user running SeaMonkey. (CVE-2011-0077)

A flaw was found in the way SeaMonkey handled the HTML iframe tag. A
web page with an iframe tag containing a specially crafted source
address could trigger this flaw, possibly leading to arbitrary code
execution with the privileges of the user running SeaMonkey.
(CVE-2011-0075)

A flaw was found in the way SeaMonkey displayed multiple marquee
elements. A malformed HTML document could cause SeaMonkey to execute
arbitrary code with the privileges of the user running SeaMonkey.
(CVE-2011-0074)

A flaw was found in the way SeaMonkey handled the nsTreeSelection
element. Malformed content could cause SeaMonkey to execute arbitrary
code with the privileges of the user running SeaMonkey.
(CVE-2011-0073)

A use-after-free flaw was found in the way SeaMonkey appended frame
and iframe elements to a DOM tree when the NoScript add-on was
enabled. Malicious HTML content could cause SeaMonkey to execute
arbitrary code with the privileges of the user running SeaMonkey.
(CVE-2011-0072)

All SeaMonkey users should upgrade to these updated packages, which
correct these issues. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a261e2a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017469.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd258156"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/02");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-chat-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-devel-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-mail-1.0.9-70.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-70.el4.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-chat / seamonkey-devel / etc");
}
