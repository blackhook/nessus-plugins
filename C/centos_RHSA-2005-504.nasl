#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:504 and 
# CentOS Errata and Security Advisory 2005:504 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21834);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0488");
  script_xref(name:"RHSA", value:"2005:504");

  script_name(english:"CentOS 3 / 4 : telnet (CESA-2005:504)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated telnet packages that fix an information disclosure issue are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The telnet package provides a command line telnet client.

Gael Delalleau discovered an information disclosure issue in the way
the telnet client handles messages from a server. An attacker could
construct a malicious telnet server that collects information from the
environment of any victim who connects to it. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0488 to this issue.

Users of telnet should upgrade to this updated package, which contains
a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011858.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9a14a6c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d284630d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8672d2c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011865.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a311f545"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011867.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0993013f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011869.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fde23ad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected telnet packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:telnet-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/14");
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
if (rpm_check(release:"CentOS-3", reference:"telnet-0.17-26.EL3.3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"telnet-server-0.17-26.EL3.3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"telnet-0.17-31.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"telnet-server-0.17-31.EL4.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "telnet / telnet-server");
}
