#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0420 and 
# CentOS Errata and Security Advisory 2006:0420 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21899);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");
  script_bugtraq_id(17682);
  script_xref(name:"RHSA", value:"2006:0420");

  script_name(english:"CentOS 3 / 4 : ethereal (CESA-2006:0420)");
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

Several denial of service bugs were found in Ethereal's protocol
dissectors. Ethereal could crash or stop responding if it reads a
malformed packet off the network. (CVE-2006-1932, CVE-2006-1933,
CVE-2006-1937, CVE-2006-1938, CVE-2006-1939, CVE-2006-1940)

Several buffer overflow bugs were found in Ethereal's COPS, telnet,
and ALCAP dissectors as well as Network Instruments file code and
NetXray/Windows Sniffer file code. Ethereal could crash or execute
arbitrary code if it reads a malformed packet off the network.
(CVE-2006-1934, CVE-2006-1935, CVE-2006-1936)

Users of ethereal should upgrade to these updated packages containing
version 0.99.0, which is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf191a09"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1b382b4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012866.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?369667bd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012868.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a1ed3f3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012875.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73b7a77c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e62c7e5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ethereal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ethereal-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/03");
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
if (rpm_check(release:"CentOS-3", reference:"ethereal-0.99.0-EL3.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ethereal-gnome-0.99.0-EL3.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"ethereal-0.99.0-EL4.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ethereal-gnome-0.99.0-EL4.2")) flag++;


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
