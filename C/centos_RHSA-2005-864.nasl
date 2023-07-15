#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:864 and 
# CentOS Errata and Security Advisory 2005:864 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21970);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3631");
  script_xref(name:"RHSA", value:"2005:864");

  script_name(english:"CentOS 4 : udev (CESA-2005:864)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated udev packages that fix a security issue are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The udev package contains an implementation of devfs in userspace
using sysfs and /sbin/hotplug.

Richard Cunningham discovered a flaw in the way udev sets permissions
on various files in /dev/input. It may be possible for an
authenticated attacker to gather sensitive data entered by a user at
the console, such as passwords. The Common Vulnerabilities and
Exposures project has assigned the name CVE-2005-3631 to this issue.

All users of udev should upgrade to these updated packages, which
contain a backported patch and are not vulnerable to this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-December/012496.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37fc9be7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-December/012523.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8be886dc"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-December/012524.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92e43af4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected udev package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/20");
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
if (rpm_check(release:"CentOS-4", reference:"udev-039-10.10.EL4.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "udev");
}
