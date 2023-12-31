#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0509 and 
# CentOS Errata and Security Advisory 2013:0509 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65143);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-4517", "CVE-2012-4518");
  script_bugtraq_id(55890);
  script_xref(name:"RHSA", value:"2013:0509");

  script_name(english:"CentOS 6 : ibacm / ibsim / ibutils / infiniband-diags / infinipath-psm / libibmad / libibumad / etc (CESA-2013:0509)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated RDMA packages that fix multiple security issues, various bugs,
and add an enhancement are now available for Red Hat Enterprise Linux
6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Enterprise Linux includes a collection of InfiniBand and iWARP
utilities, libraries and development packages for writing applications
that use Remote Direct Memory Access (RDMA) technology.

A denial of service flaw was found in the way ibacm managed reference
counts for multicast connections. An attacker could send specially
crafted multicast packets that would cause the ibacm daemon to crash.
(CVE-2012-4517)

It was found that the ibacm daemon created some files with
world-writable permissions. A local attacker could use this flaw to
overwrite the contents of the ibacm.log or ibacm.port file, allowing
them to mask certain actions from the log or cause ibacm to run on a
non-default port. (CVE-2012-4518)

CVE-2012-4518 was discovered by Florian Weimer of the Red Hat Product
Security Team and Kurt Seifried of the Red Hat Security Response Team.

The InfiniBand/iWARP/RDMA stack components have been upgraded to more
recent upstream versions.

This update also fixes the following bugs :

* Previously, the 'ibnodes -h' command did not show a proper usage
message. With this update the problem is fixed and 'ibnodes -h' now
shows the correct usage message. (BZ#818606)

* Previously, the ibv_devinfo utility erroneously showed iWARP cxgb3
hardware's physical state as invalid even when the device was working.
For iWARP hardware, the phys_state field has no meaning. This update
patches the utility to not print out anything for this field when the
hardware is iWARP hardware. (BZ#822781)

* Prior to the release of Red Hat Enterprise Linux 6.3, the kernel
created the InfiniBand device files in the wrong place and a udev
rules file was used to force the devices to be created in the proper
place. With the update to 6.3, the kernel was fixed to create the
InfiniBand device files in the proper place, and so the udev rules
file was removed as no longer being necessary. However, a bug in the
kernel device creation meant that, although the devices were now being
created in the right place, they had incorrect permissions.
Consequently, when users attempted to run an RDMA application as a
non-root user, the application failed to get the necessary permissions
to use the RDMA device and the application terminated. This update
puts a new udev rules file in place. It no longer attempts to create
the InfiniBand devices since they already exist, but it does correct
the device permissions on the files. (BZ#834428)

* Previously, using the 'perfquery -C' command with a host name caused
the perfquery utility to become unresponsive. The list of controllers
to process was never cleared and the process looped infinitely on a
single controller. A patch has been applied to make sure that in the
case where the user passes in the -C option, the controller list is
cleared out once that controller has been processed. As a result,
perfquery now works as expected in the scenario described. (BZ#847129)

* The OpenSM init script did not handle the case where there were no
configuration files under '/etc/rdma/opensm.conf.*'. With this update,
the script as been patched and the InfiniBand Subnet Manager, OpenSM,
now starts as expected in the scenario described. (BZ#862857)

This update also adds the following enhancement :

* This update provides an updated mlx4_ib Mellanox driver which
includes Single Root I/O Virtualization (SR-IOV) support. (BZ#869737)

All users of RDMA are advised to upgrade to these updated packages,
which fix these issues and add this enhancement."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019346.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29e13daa"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019347.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b5e76d8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88d52872"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0a73691"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019373.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d1ddc1c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019374.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5866e7f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019375.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3edccfda"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019380.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f613a535"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019383.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0ab7e46"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019457.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa8bbab7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019488.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f1d1da9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000534.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a0fd188"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000535.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?038dc4ed"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000536.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9c32a65"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000538.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69ba8017"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000539.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db9a967f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000565.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42250031"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000566.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?799060ea"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000570.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bfe0026"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000573.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1ba9c1d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000648.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd6e5f64"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000679.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69d393b9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4517");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibsim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibutils-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:infiniband-diags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:infiniband-diags-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:infiniband-diags-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:infinipath-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:infinipath-psm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibmad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibmad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibmad-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibumad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibumad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibumad-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibverbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibverbs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibverbs-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibverbs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmlx4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmlx4-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librdmacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librdmacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librdmacm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librdmacm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:opensm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:opensm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:opensm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:opensm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rdma");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"ibacm-1.0.8-0.git7a3adb7.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ibacm-devel-1.0.8-0.git7a3adb7.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ibsim-0.5-7.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ibutils-1.5.7-7.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ibutils-devel-1.5.7-7.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ibutils-libs-1.5.7-7.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"infiniband-diags-1.5.12-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"infiniband-diags-devel-1.5.12-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"infiniband-diags-devel-static-1.5.12-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"infinipath-psm-3.0.1-115.1015_open.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"infinipath-psm-devel-3.0.1-115.1015_open.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibmad-1.3.9-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibmad-devel-1.3.9-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibmad-static-1.3.9-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibumad-1.3.8-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibumad-devel-1.3.8-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibumad-static-1.3.8-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibverbs-1.1.6-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibverbs-devel-1.1.6-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibverbs-devel-static-1.1.6-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibverbs-utils-1.1.6-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libmlx4-1.0.4-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libmlx4-static-1.0.4-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"librdmacm-1.0.17-0.git4b5c1aa.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"librdmacm-devel-1.0.17-0.git4b5c1aa.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"librdmacm-static-1.0.17-0.git4b5c1aa.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"librdmacm-utils-1.0.17-0.git4b5c1aa.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"opensm-3.3.15-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"opensm-devel-3.3.15-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"opensm-libs-3.3.15-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"opensm-static-3.3.15-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rdma-3.6-1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ibacm / ibacm-devel / ibsim / ibutils / ibutils-devel / etc");
}
