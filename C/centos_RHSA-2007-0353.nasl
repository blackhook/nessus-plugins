#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0353 and 
# CentOS Errata and Security Advisory 2007:0353 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25255);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1558");
  script_bugtraq_id(23257);
  script_xref(name:"RHSA", value:"2007:0353");

  script_name(english:"CentOS 3 / 4 : evolution (CESA-2007:0353)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that fix a security bug are now available
for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Evolution is the GNOME collection of personal information management
(PIM) tools.

A flaw was found in the way Evolution processed certain APOP
authentication requests. A remote attacker could potentially acquire
certain portions of a user's authentication credentials by sending
certain responses when evolution-data-server attempted to authenticate
against an APOP server. (CVE-2007-1558)

All users of Evolution should upgrade to these updated packages, which
contain a backported patch which resolves this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013767.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0978fc61"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06dd0f9a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013773.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83675596"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013774.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?752824f7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013784.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b02b1dd0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013785.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07f449d9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/20");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"evolution-1.4.5-20.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"evolution-devel-1.4.5-20.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"evolution-2.0.2-35.0.2.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution-devel-2.0.2-35.0.2.el4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution / evolution-devel");
}
