#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0727 and 
# CentOS Errata and Security Advisory 2006:0727 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37714);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3011", "CVE-2006-4810");
  script_bugtraq_id(14854, 20959);
  script_xref(name:"RHSA", value:"2006:0727");

  script_name(english:"CentOS 3 / 4 : texinfo (CESA-2006:0727)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Texinfo packages that fix various security vulnerabilities are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Texinfo is a documentation system that can produce both online
information and printed output from a single source file.

A buffer overflow flaw was found in Texinfo's texindex command. An
attacker could construct a carefully crafted Texinfo file that could
cause texindex to crash or possibly execute arbitrary code when
opened. (CVE-2006-4810)

A flaw was found in the way Texinfo's texindex command creates
temporary files. A local user could leverage this flaw to overwrite
files the user executing texindex has write access to. (CVE-2005-3011)

Users of Texinfo should upgrade to these updated packages which
contain backported patches and are not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f91cdb2f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013372.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44952730"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013373.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cec4dedf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013385.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db022d1e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013386.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8813b5bb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected texinfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"info-4.5-3.el3.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"texinfo-4.5-3.el3.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"info-4.7-5.el4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"info-4.7-5.el4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"texinfo-4.7-5.el4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"texinfo-4.7-5.el4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "info / texinfo");
}
