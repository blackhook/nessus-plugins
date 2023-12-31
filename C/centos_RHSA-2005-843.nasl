#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:843 and 
# CentOS Errata and Security Advisory 2005:843 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21874);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3632", "CVE-2005-3662");
  script_bugtraq_id(15427, 15514);
  script_xref(name:"RHSA", value:"2005:843");

  script_name(english:"CentOS 3 : netpbm (CESA-2005:843)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated netpbm packages that fix two security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The netpbm package contains a library of functions that support
programs for handling various graphics file formats.

A stack based buffer overflow bug was found in the way netpbm converts
Portable Anymap (PNM) files into Portable Network Graphics (PNG). A
specially crafted PNM file could allow an attacker to execute
arbitrary code by attempting to convert a PNM file to a PNG file when
using pnmtopng with the '-text' option. The Common Vulnerabilities and
Exposures project has assigned the name CVE-2005-3632 to this issue.

An 'off by one' bug was found in the way netpbm converts Portable
Anymap (PNM) files into Portable Network Graphics (PNG). If a victim
attempts to convert a specially crafted 256 color PNM file to a PNG
file, then it can cause the pnmtopng utility to crash. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-3662 to this issue.

All users of netpbm should upgrade to these updated packages, which
contain backported patches that resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-December/012480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98560b19"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-December/012481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a4715af"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-December/012489.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31a9e645"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected netpbm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/20");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"netpbm-9.24-11.30.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"netpbm-devel-9.24-11.30.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"netpbm-progs-9.24-11.30.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "netpbm / netpbm-devel / netpbm-progs");
}
