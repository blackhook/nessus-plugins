#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0344 and 
# CentOS Errata and Security Advisory 2007:0344 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25353);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1558");
  script_bugtraq_id(23257);
  script_xref(name:"RHSA", value:"2007:0344");

  script_name(english:"CentOS 5 : evolution-data-server (CESA-2007:0344)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution-data-server package that fixes a security bug are
now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The evolution-data-server package provides a unified backend for
programs that work with contacts, tasks, and calendar information.

A flaw was found in the way evolution-data-server processed certain
APOP authentication requests. By sending certain responses when
evolution-data-server attempted to authenticate against an APOP
server, a remote attacker could potentially acquire certain portions
of a user's authentication credentials. (CVE-2007-1558)

All users of evolution-data-server should upgrade to these updated
packages, which contain a backported patch which resolves this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0468014e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013836.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?554a0c61"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution-data-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/01");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"evolution-data-server-1.8.0-15.0.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"evolution-data-server-devel-1.8.0-15.0.3.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution-data-server / evolution-data-server-devel");
}
