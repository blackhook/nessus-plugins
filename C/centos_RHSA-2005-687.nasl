#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:687 and 
# CentOS Errata and Security Advisory 2005:687 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21850);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2360", "CVE-2005-2361", "CVE-2005-2362", "CVE-2005-2363", "CVE-2005-2364", "CVE-2005-2365", "CVE-2005-2366", "CVE-2005-2367");
  script_bugtraq_id(14399);
  script_xref(name:"RHSA", value:"2005:687");

  script_name(english:"CentOS 3 / 4 : ethereal (CESA-2005:687)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Ethereal packages that fix various security vulnerabilities
are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The ethereal package is a program for monitoring network traffic.

A number of security flaws have been discovered in Ethereal. On a
system where Ethereal is running, a remote attacker could send
malicious packets to trigger these flaws and cause Ethereal to crash
or potentially execute arbitrary code. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the names
CVE-2005-2360, CVE-2005-2361, CVE-2005-2362, CVE-2005-2363,
CVE-2005-2364, CVE-2005-2365, CVE-2005-2366, and CVE-2005-2367 to
these issues.

Users of ethereal should upgrade to these updated packages, which
contain version 0.10.12 which is not vulnerable to these issues.

Note: To reduce the risk of future vulnerabilities in Ethereal, the
ethereal and tethereal programs in this update have been compiled as
Position Independent Executables (PIE) for Red Hat Enterprise Linux 3
and 4. In addition FORTIFY_SOURCE has been enabled for Red Hat
Enterprise Linux 4 packages to provide compile time and runtime buffer
checks."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012053.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43f441a1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012054.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b10bbd55"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012057.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?149086dd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012058.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bcbb18c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012062.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a42071bc"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012063.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ab090a1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ethereal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ethereal-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"ethereal-0.10.12-1.EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"ethereal-gnome-0.10.12-1.EL3.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"ethereal-0.10.12-1.EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ethereal-gnome-0.10.12-1.EL4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ethereal / ethereal-gnome");
}
