#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0280 and 
# CentOS Errata and Security Advisory 2006:0280 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21991);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-1550");
  script_xref(name:"RHSA", value:"2006:0280");

  script_name(english:"CentOS 4 : dia (CESA-2006:0280)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Dia package that fixes several buffer overflow bugs are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Dia drawing program is designed to draw various types of diagrams.

infamous41md discovered three buffer overflow bugs in Dia's xfig file
format importer. If an attacker is able to trick a Dia user into
opening a carefully crafted xfig file, it may be possible to execute
arbitrary code as the user running Dia. (CVE-2006-1550)

Users of Dia should update to these erratum packages, which contain
backported patches and are not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9109a15e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012879.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd78ed4a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012880.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d8e7d52"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dia package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dia");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"dia-0.94-5.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dia");
}
