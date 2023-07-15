#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0156 and 
# CentOS Errata and Security Advisory 2006:0156 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21883);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3313", "CVE-2005-3651", "CVE-2005-4585");
  script_bugtraq_id(15219, 15794, 16076);
  script_xref(name:"RHSA", value:"2006:0156");

  script_name(english:"CentOS 3 / 4 : ethereal (CESA-2006:0156)");
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

Ethereal is a program for monitoring network traffic.

Two denial of service bugs were found in Ethereal's IRC and GTP
protocol dissectors. Ethereal could crash or stop responding if it
reads a malformed IRC or GTP packet off the network. The Common
Vulnerabilities and Exposures project (cve.mitre.org) assigned the
names CVE-2005-3313 and CVE-2005-4585 to these issues.

A buffer overflow bug was found in Ethereal's OSPF protocol dissector.
Ethereal could crash or execute arbitrary code if it reads a malformed
OSPF packet off the network. (CVE-2005-3651)

Users of ethereal should upgrade to these updated packages containing
version 0.10.14, which is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012555.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1cd7238c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012556.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92b2405c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65b5343a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012568.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be970ccf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012575.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2064676c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012576.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93e59d63"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ethereal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ethereal-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/12");
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
if (rpm_check(release:"CentOS-3", reference:"ethereal-0.10.14-1.EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ethereal-gnome-0.10.14-1.EL3.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"ethereal-0.10.14-1.EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ethereal-gnome-0.10.14-1.EL4.1")) flag++;


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
