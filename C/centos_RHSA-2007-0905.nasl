#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0905 and 
# CentOS Errata and Security Advisory 2007:0905 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26973);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-3820", "CVE-2007-4224", "CVE-2007-4569");
  script_bugtraq_id(24912);
  script_xref(name:"RHSA", value:"2007:0905");

  script_name(english:"CentOS 4 / 5 : kdebase (CESA-2007:0905)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdebase packages that resolve several security flaws are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The kdebase packages provide the core applications for KDE, the K
Desktop Environment. These core packages include Konqueror, the web
browser and file manager.

These updated packages address the following vulnerabilities :

Kees Huijgen found a flaw in the way KDM handled logins when autologin
and 'shutdown with password' were enabled. A local user would have
been able to login via KDM as any user without requiring a password.
(CVE-2007-4569)

Two Konqueror address spoofing flaws were discovered. A malicious
website could spoof the Konqueror address bar, tricking a victim into
believing the page was from a different site. (CVE-2007-3820,
CVE-2007-4224)

Users of KDE should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014285.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c583dbe4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014294.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21121cef"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70b9641a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014298.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96790c92"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014299.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?996c6225"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"kdebase-3.3.1-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdebase-devel-3.3.1-6.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"kdebase-3.5.4-15.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdebase-devel-3.5.4-15.el5.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase / kdebase-devel");
}
