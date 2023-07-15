#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0322 and 
# CentOS Errata and Security Advisory 2007:0322 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25150);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1859");
  script_bugtraq_id(23783);
  script_xref(name:"RHSA", value:"2007:0322");

  script_name(english:"CentOS 3 : xscreensaver (CESA-2007:0322)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated xscreensaver package that fixes a security flaw is now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

XScreenSaver is a collection of screensavers.

Alex Yamauchi discovered a flaw in the way XScreenSaver verifies user
passwords. When a system is using a remote directory service for login
credentials, a local attacker may be able to cause a network outage
causing XScreenSaver to crash, unlocking the screen. (CVE-2007-1859)

Users of XScreenSaver should upgrade to this updated package, which
contains a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013712.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b35a492"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7101d364"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013714.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d6add91"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xscreensaver package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xscreensaver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/03");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"xscreensaver-4.10-21.el3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xscreensaver");
}
