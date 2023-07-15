#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0599 and 
# CentOS Errata and Security Advisory 2008:0599 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33526);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-2785");
  script_bugtraq_id(29802);
  script_xref(name:"RHSA", value:"2008:0599");

  script_name(english:"CentOS 3 / 4 : seamonkey (CESA-2008:0599)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix a security issue are now available
for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 16th July 2008] The original set of packages for Red Hat
Enterprise Linux 4 were missing the seamonkey-nss and seamonkey-nspr
packages. This errata was updated to add these missing packages.

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

An integer overflow flaw was found in the way SeaMonkey displayed
certain web content. A malicious website could cause SeaMonkey to
crash or execute arbitrary code with the permissions of the user
running SeaMonkey. (CVE-2008-2785)

All seamonkey users should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015132.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a527efee"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a759c436"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7dc697a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015139.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27d47723"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015140.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe86edaf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd97c043"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"seamonkey-1.0.9-0.22.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-chat-1.0.9-0.22.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-devel-1.0.9-0.22.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-dom-inspector-1.0.9-0.22.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-js-debugger-1.0.9-0.22.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-mail-1.0.9-0.22.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-1.0.9-0.22.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-devel-1.0.9-0.22.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-1.0.9-0.22.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-devel-1.0.9-0.22.el3.centos3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-0.10-0.8.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-0.10-0.8.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-devel-0.10-0.8.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-devel-0.10-0.8.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-1.0.9-16.4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-chat-1.0.9-16.4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-devel-1.0.9-16.4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-dom-inspector-1.0.9-16.4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-js-debugger-1.0.9-16.4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-mail-1.0.9-16.4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nspr-1.0.9-16.4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nspr-devel-1.0.9-16.4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nss-1.0.9-16.4.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nss-devel-1.0.9-16.4.el4.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / seamonkey / seamonkey-chat / etc");
}
