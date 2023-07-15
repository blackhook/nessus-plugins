#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1244 and 
# CentOS Errata and Security Advisory 2011:1244 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56073);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_xref(name:"RHSA", value:"2011:1244");

  script_name(english:"CentOS 4 : seamonkey (CESA-2011:1244)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix one security issue are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact.

SeaMonkey is an open source web browser, email and newsgroup client,
IRC chat client, and HTML editor.

It was found that a Certificate Authority (CA) issued a fraudulent
HTTPS certificate. This update renders any HTTPS certificates signed
by that CA as untrusted, except for a select few. The now untrusted
certificates that were issued before July 1, 2011 can be manually
re-enabled and used again at your own risk in SeaMonkey; however,
affected certificates issued after this date cannot be re-enabled or
used. (BZ#734316)

All SeaMonkey users should upgrade to these updated packages, which
correct this issue. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017716.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5263ed0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017717.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4c645d6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/06");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-chat-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-devel-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"seamonkey-mail-1.0.9-74.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-74.el4.centos")) flag++;


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
