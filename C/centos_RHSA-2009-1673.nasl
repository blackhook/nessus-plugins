#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1673 and 
# CentOS Errata and Security Advisory 2009:1673 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43355);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3981", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986");
  script_xref(name:"RHSA", value:"2009:1673");

  script_name(english:"CentOS 4 : seamonkey (CESA-2009:1673)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix several security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, email and newsgroup client,
IRC chat client, and HTML editor.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code with the privileges of the
user running SeaMonkey. (CVE-2009-3979)

A flaw was found in the SeaMonkey NT Lan Manager (NTLM) authentication
protocol implementation. If an attacker could trick a local user that
has NTLM credentials into visiting a specially crafted web page, they
could send arbitrary requests, authenticated with the user's NTLM
credentials, to other applications on the user's system.
(CVE-2009-3983)

A flaw was found in the way SeaMonkey displayed the SSL location bar
indicator. An attacker could create an unencrypted web page that
appears to be encrypted, possibly tricking the user into believing
they are visiting a secure page. (CVE-2009-3984)

All SeaMonkey users should upgrade to these updated packages, which
correct these issues. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-December/016395.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6284a65"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-December/016396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70072831"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/21");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-chat-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-devel-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-mail-1.0.9-51.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-51.el4.centos")) flag++;


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
