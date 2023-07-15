#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0557 and 
# CentOS Errata and Security Advisory 2010:0557 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47866);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-2755");
  script_xref(name:"RHSA", value:"2010:0557");

  script_name(english:"CentOS 3 / 4 : seamonkey (CESA-2010:0557)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix a security issue are now available
for Red Hat Enterprise Linux 3 and 4.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

SeaMonkey is an open source web browser, email and newsgroup client,
IRC chat client, and HTML editor.

An invalid free flaw was found in SeaMonkey's plugin handler.
Malicious web content could result in an invalid memory pointer being
freed, causing SeaMonkey to crash or, potentially, execute arbitrary
code with the privileges of the user running SeaMonkey.
(CVE-2010-2755)

All SeaMonkey users should upgrade to these updated packages, which
correct this issue. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016926.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a88e9ec6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016927.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b15e71a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dfd6175"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30101fa1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/28");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-chat-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-devel-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-mail-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-nspr-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-nspr-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-nspr-devel-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-nss-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-nss-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"seamonkey-nss-devel-1.0.9-0.58.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"seamonkey-nss-devel-1.0.9-0.58.el3.centos3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-chat-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-devel-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-mail-1.0.9-60.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-60.el4.centos")) flag++;


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
