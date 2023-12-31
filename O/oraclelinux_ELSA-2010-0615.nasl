#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0615 and 
# Oracle Linux Security Advisory ELSA-2010-0615 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68082);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-2239", "CVE-2010-2242");
  script_bugtraq_id(41981);
  script_xref(name:"RHSA", value:"2010:0615");

  script_name(english:"Oracle Linux 5 : libvirt (ELSA-2010-0615)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0615 :

Updated libvirt packages that fix two security issues and three bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remotely managing virtualized
systems.

It was found that libvirt did not set the user-defined backing store
format when creating a new image, possibly resulting in applications
having to probe the backing store to discover the format. A privileged
guest user could use this flaw to read arbitrary files on the host.
(CVE-2010-2239)

It was found that libvirt created insecure iptables rules on the host
when a guest system was configured for IP masquerading, allowing the
guest to use privileged ports on the host when accessing network
resources. A privileged guest user could use this flaw to access
network resources that would otherwise not be accessible to the guest.
(CVE-2010-2242)

Red Hat would like to thank Jeremy Nickurak for reporting the
CVE-2010-2242 issue.

This update also fixes the following bugs :

* a Linux software bridge assumes the MAC address of the enslaved
interface with the numerically lowest MAC address. When the bridge
changes its MAC address, for a period of time it does not relay
packets across network segments, resulting in a temporary network
'blackout'. The bridge should thus avoid changing its MAC address in
order not to disrupt network communications.

The Linux kernel assigns network TAP devices a random MAC address.
Occasionally, this random MAC address is lower than that of the
physical interface which is enslaved (for example, eth0 or eth1),
which causes the bridge to change its MAC address, thereby disrupting
network communications for a period of time.

With this update, libvirt now sets an explicit MAC address for all TAP
devices created using the configured MAC address from the XML, but
with the high bit set to 0xFE. The result is that TAP device MAC
addresses are now numerically greater than those for physical
interfaces, and bridges should no longer attempt to switch their MAC
address to that of the TAP device, thus avoiding potential spurious
network disruptions. (BZ#617243)

* a memory leak in the libvirt driver for the Xen hypervisor has been
fixed with this update. (BZ#619711)

* the xm and virsh management user interfaces for virtual guests can
be called on the command line to list the number of active guests.
However, under certain circumstances, running the 'virsh list' command
resulted in virsh not listing all of the virtual guests that were
active (that is, running) at the time. This update incorporates a fix
that matches the logic used for determining active guests with that of
'xm list', such that both commands should now list the same number of
active virtual guests under all circumstances. (BZ#618200)

All users of libvirt are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, the system must be rebooted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-August/001595.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"libvirt-0.6.3-33.0.1.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"libvirt-devel-0.6.3-33.0.1.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"libvirt-python-0.6.3-33.0.1.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-devel / libvirt-python");
}
