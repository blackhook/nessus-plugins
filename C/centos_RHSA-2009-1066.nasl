#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1066 and 
# CentOS Errata and Security Advisory 2009:1066 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38930);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1381", "CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1581");
  script_xref(name:"RHSA", value:"2009:1066");

  script_name(english:"CentOS 3 / 5 : squirrelmail (CESA-2009:1066)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

SquirrelMail is a standards-based webmail package written in PHP.

A server-side code injection flaw was found in the SquirrelMail
'map_yp_alias' function. If SquirrelMail was configured to retrieve a
user's IMAP server address from a Network Information Service (NIS)
server via the 'map_yp_alias' function, an unauthenticated, remote
attacker using a specially crafted username could use this flaw to
execute arbitrary code with the privileges of the web server.
(CVE-2009-1579)

Multiple cross-site scripting (XSS) flaws were found in SquirrelMail.
An attacker could construct a carefully crafted URL, which once
visited by an unsuspecting user, could cause the user's web browser to
execute malicious script in the context of the visited SquirrelMail
web page. (CVE-2009-1578)

It was discovered that SquirrelMail did not properly sanitize
Cascading Style Sheets (CSS) directives used in HTML mail. A remote
attacker could send a specially crafted email that could place mail
content above SquirrelMail's controls, possibly allowing phishing and
cross-site scripting attacks. (CVE-2009-1581)

Users of squirrelmail should upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015945.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f75d4be"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015946.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?166111da"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015947.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6dc56e3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015948.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca17c7b1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"squirrelmail-1.4.8-13.el3.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"squirrelmail-1.4.8-13.el3.centos.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"squirrelmail-1.4.8-5.el5.centos.7")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squirrelmail");
}
