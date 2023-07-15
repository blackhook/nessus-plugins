#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2229 and 
# CentOS Errata and Security Advisory 2019:2229 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128377);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-10893");
  script_xref(name:"RHSA", value:"2019:2229");

  script_name(english:"CentOS 7 : libgovirt / spice-gtk / spice-vdagent / virt-viewer (CESA-2019:2229)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for spice-gtk, libgovirt, spice-vdagent, and virt-viewer is
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for Simple
Protocol for Independent Computing Environments (SPICE) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of
this widget to access virtual machines using the SPICE protocol.

The libgovirt packages contain a library that allows applications to
use the oVirt Representational State Transfer (REST) API to list
virtual machines (VMs) managed by an oVirt instance. The library is
also used to get the connection parameters needed to establish a
connection to the VMs using Simple Protocol For Independent Computing
Environments (SPICE) or Virtual Network Computing (VNC).

The spice-vdagent packages provide a SPICE agent for Linux guests.

The virt-viewer packages provide Virtual Machine Viewer, which is a
lightweight interface for interacting with the graphical display of a
virtualized guest.

Security Fix(es) :

* spice-client: Insufficient encoding checks for LZ can cause
different integer/buffer overflows (CVE-2018-10893)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005946.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2997fff"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d79061b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006144.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2473952d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4abef31"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10893");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgovirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk3-vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-vdagent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgovirt-0.3.4-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgovirt-devel-0.3.4-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-glib-0.35-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-glib-devel-0.35-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-gtk-tools-0.35-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-gtk3-0.35-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-gtk3-devel-0.35-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-gtk3-vala-0.35-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-vdagent-0.14.0-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"virt-viewer-5.0-15.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgovirt / libgovirt-devel / spice-glib / spice-glib-devel / etc");
}
