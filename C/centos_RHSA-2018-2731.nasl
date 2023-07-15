#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2731 and 
# CentOS Errata and Security Advisory 2018:2731 respectively.
#

include('compat.inc');

if (description)
{
  script_id(117826);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/24");

  script_cve_id("CVE-2018-10873");
  script_xref(name:"RHSA", value:"2018:2731");

  script_name(english:"CentOS 7 : spice / spice-gtk (CESA-2018:2731)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for spice and spice-gtk is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display system built for virtual environments which allows
the user to view a computing 'desktop' environment not only on the
machine where it is running, but from anywhere on the Internet and
from a wide variety of machine architectures.

The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for Simple
Protocol for Independent Computing Environments (SPICE) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of
this widget to access virtual machines using the SPICE protocol.

Security Fix(es) :

* spice: Missing check in demarshal.py:write_validate_array_item()
allows for buffer overflow and denial of service (CVE-2018-10873)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

This issue was discovered by Frediano Ziglio (Red Hat).");
  # https://lists.centos.org/pipermail/centos-announce/2018-September/023047.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de679f08");
  # https://lists.centos.org/pipermail/centos-announce/2018-September/023048.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fc18046");
  script_set_attribute(attribute:"solution", value:
"Update the affected spice and / or spice-gtk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk3-vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-glib-0.34-3.el7_5.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-glib-devel-0.34-3.el7_5.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-gtk-tools-0.34-3.el7_5.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-gtk3-0.34-3.el7_5.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-gtk3-devel-0.34-3.el7_5.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-gtk3-vala-0.34-3.el7_5.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-server-0.14.0-2.el7_5.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-server-devel-0.14.0-2.el7_5.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-glib / spice-glib-devel / spice-gtk-tools / spice-gtk3 / etc");
}
