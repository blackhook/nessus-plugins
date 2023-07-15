#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0909 and 
# CentOS Errata and Security Advisory 2007:0909 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26974);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0242", "CVE-2007-0537", "CVE-2007-1308", "CVE-2007-1564", "CVE-2007-3820", "CVE-2007-4224");
  script_xref(name:"RHSA", value:"2007:0909");

  script_name(english:"CentOS 4 / 5 : kdelibs (CESA-2007:0909)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages that resolve several security flaws are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The kdelibs package provides libraries for the K Desktop Environment
(KDE).

Two cross-site-scripting flaws were found in the way Konqueror
processes certain HTML content. This could result in a malicious
attacker presenting misleading content to an unsuspecting user.
(CVE-2007-0242, CVE-2007-0537)

A flaw was found in KDE JavaScript implementation. A web page
containing malicious JavaScript code could cause Konqueror to crash.
(CVE-2007-1308)

A flaw was found in the way Konqueror handled certain FTP PASV
commands. A malicious FTP server could use this flaw to perform a
rudimentary port-scan of machines behind a user's firewall.
(CVE-2007-1564)

Two Konqueror address spoofing flaws have been discovered. It was
possible for a malicious website to cause the Konqueror address bar to
display information which could trick a user into believing they are
at a different website than they actually are. (CVE-2007-3820,
CVE-2007-4224)

Users of KDE should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014284.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4576e16d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014292.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?daa3b324"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014293.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fce9c47"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014300.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb2b04c0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014301.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d8637c9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(59, 79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/08");
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
if (rpm_check(release:"CentOS-4", reference:"kdelibs-3.3.1-9.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdelibs-devel-3.3.1-9.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"kdelibs-3.5.4-13.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdelibs-apidocs-3.5.4-13.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdelibs-devel-3.5.4-13.el5.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-apidocs / kdelibs-devel");
}
