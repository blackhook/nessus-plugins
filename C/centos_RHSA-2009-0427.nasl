#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0427 and 
# CentOS Errata and Security Advisory 2009:0427 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43742);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1185");
  script_bugtraq_id(34536);
  script_xref(name:"RHSA", value:"2009:0427");

  script_name(english:"CentOS 5 : udev (CESA-2009:0427)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated udev packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

udev provides a user-space API and implements a dynamic device
directory, providing only the devices present on the system. udev
replaces devfs in order to provide greater hot plug functionality.
Netlink is a datagram oriented service, used to transfer information
between kernel modules and user-space processes.

It was discovered that udev did not properly check the origin of
Netlink messages. A local attacker could use this flaw to gain root
privileges via a crafted Netlink message sent to udev, causing it to
create a world-writable block device file for an existing system block
device (for example, the root file system). (CVE-2009-1185)

Red Hat would like to thank Sebastian Krahmer of the SUSE Security
Team for responsibly reporting this flaw.

Users of udev are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, the udevd daemon will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015796.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06228205"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015797.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b74478d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected udev packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux udev Netlink Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvolume_id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvolume_id-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"libvolume_id-095-14.20.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvolume_id-devel-095-14.20.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"udev-095-14.20.el5_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvolume_id / libvolume_id-devel / udev");
}
