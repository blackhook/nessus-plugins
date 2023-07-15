#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0777 and 
# CentOS Errata and Security Advisory 2007:0777 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25850);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-3381");
  script_xref(name:"RHSA", value:"2007:0777");

  script_name(english:"CentOS 5 : gdm (CESA-2007:0777)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gdm package that fixes a security issue is now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Gdm (the GNOME Display Manager) is a highly configurable
reimplementation of xdm, the X Display Manager. Gdm allows you to log
into your system with the X Window System running and supports running
several different X sessions on your local machine at the same time.

A flaw was found in the way Gdm listens on its unix domain socket. A
local user could crash a running X session by writing malicious data
to Gdm's unix domain socket. (CVE-2007-3381)

All users of gdm should upgrade to this updated package, which
contains a backported patch that resolves this issue.

Red Hat would like to thank JLANTHEA for reporting this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16d0ee0a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014144.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26d4bef0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdm package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/13");
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
if (rpm_check(release:"CentOS-5", reference:"gdm-2.16.0-31.0.1.el5.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm");
}
