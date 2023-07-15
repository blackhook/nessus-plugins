#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0680 and 
# CentOS Errata and Security Advisory 2010:0680 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49181);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-2753", "CVE-2010-2760", "CVE-2010-2763", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-2770", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");
  script_bugtraq_id(43045);
  script_xref(name:"RHSA", value:"2010:0680");

  script_name(english:"CentOS 3 / 4 : seamonkey (CESA-2010:0680)");
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

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

SeaMonkey is an open source web browser, email and newsgroup client,
IRC chat client, and HTML editor.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code with the privileges of the
user running SeaMonkey. (CVE-2010-3169)

A buffer overflow flaw was found in SeaMonkey. A web page containing
malicious content could cause SeaMonkey to crash or, potentially,
execute arbitrary code with the privileges of the user running
SeaMonkey. (CVE-2010-2765)

A use-after-free flaw and several dangling pointer flaws were found in
SeaMonkey. A web page containing malicious content could cause
SeaMonkey to crash or, potentially, execute arbitrary code with the
privileges of the user running SeaMonkey. (CVE-2010-2760,
CVE-2010-2767, CVE-2010-3167, CVE-2010-3168)

A cross-site scripting (XSS) flaw was found in SeaMonkey. A web page
containing malicious content could cause SeaMonkey to run JavaScript
code with the permissions of a different website. (CVE-2010-2768)

All SeaMonkey users should upgrade to these updated packages, which
correct these issues. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72984d34"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016963.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64a3ecfa"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d63d018"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016971.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f36d15dd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/12");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-chat-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-devel-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-mail-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-nspr-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-nspr-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-nspr-devel-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-nss-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-nss-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-nss-devel-1.0.9-0.60.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-nss-devel-1.0.9-0.60.el3.centos3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-chat-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-devel-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-mail-1.0.9-63.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-63.el4.centos")) flag++;


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
