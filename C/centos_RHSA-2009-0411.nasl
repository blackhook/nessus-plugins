#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0411 and 
# CentOS Errata and Security Advisory 2009:0411 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38896);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0115");
  script_xref(name:"RHSA", value:"2009:0411");

  script_name(english:"CentOS 4 / 5 : device-mapper-multipath (CESA-2009:0411)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated device-mapper-multipath packages that fix a security issue are
now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The device-mapper multipath packages provide tools to manage multipath
devices by issuing instructions to the device-mapper multipath kernel
module, and by managing the creation and removal of partitions for
device-mapper devices.

It was discovered that the multipathd daemon set incorrect permissions
on the socket used to communicate with command line clients. An
unprivileged, local user could use this flaw to send commands to
multipathd, resulting in access disruptions to storage devices
accessible via multiple paths and, possibly, file system corruption on
these devices. (CVE-2009-0115)

Users of device-mapper-multipath are advised to upgrade to these
updated packages, which contain a backported patch to resolve this
issue. The multipathd service must be restarted for the changes to
take effect.

Important: the version of the multipathd daemon in Red Hat Enterprise
Linux 5 has a known issue which may cause a machine to become
unresponsive when the multipathd service is stopped. This issue is
tracked in the Bugzilla bug #494582; a link is provided in the
References section of this erratum. Until this issue is resolved, we
recommend restarting the multipathd service by issuing the following
commands in sequence :

# killall -KILL multipathd

# service multipathd restart"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015728.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dda51ca"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015738.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d680e0ed"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015739.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?231c710e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015910.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68541532"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015911.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?616a790f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected device-mapper-multipath packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:device-mapper-multipath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kpartx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/26");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"device-mapper-multipath-0.4.5-31.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"device-mapper-multipath-0.4.5-31.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"device-mapper-multipath-0.4.5-31.el4_7.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"device-mapper-multipath-0.4.7-23.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kpartx-0.4.7-23.el5_3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "device-mapper-multipath / kpartx");
}
