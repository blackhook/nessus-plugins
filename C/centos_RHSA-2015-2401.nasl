#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2401 and 
# CentOS Errata and Security Advisory 2015:2401 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87157);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-5281");
  script_xref(name:"RHSA", value:"2015:2401");

  script_name(english:"CentOS 7 : grub2 (CESA-2015:2401)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated grub2 packages that fix one security issue, several bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The grub2 packages provide version 2 of the Grand Unified Bootloader
(GRUB), a highly configurable and customizable bootloader with modular
architecture. The packages support a variety of kernel formats, file
systems, computer architectures, and hardware devices.

It was discovered that grub2 builds for EFI systems contained modules
that were not suitable to be loaded in a Secure Boot environment. An
attacker could use this flaw to circumvent the Secure Boot mechanisms
and load non-verified code. Attacks could use the boot menu if no
password was set, or the grub2 configuration file if the attacker has
root privileges on the system. (CVE-2015-5281)

This update also fixes the following bugs :

* In one of the earlier updates, GRUB2 was modified to escape forward
slash (/) characters in several different places. In one of these
places, the escaping was unnecessary and prevented certain types of
kernel command-line arguments from being passed to the kernel
correctly. With this update, GRUB2 no longer escapes the forward slash
characters in the mentioned place, and the kernel command-line
arguments work as expected. (BZ#1125404)

* Previously, GRUB2 relied on a timing mechanism provided by legacy
hardware, but not by the Hyper-V Gen2 hypervisor, to calibrate its
timer loop. This prevented GRUB2 from operating correctly on Hyper-V
Gen2. This update modifies GRUB2 to use a different mechanism on
Hyper-V Gen2 to calibrate the timing. As a result, Hyper-V Gen2
hypervisors now work as expected. (BZ#1150698)

* Prior to this update, users who manually configured GRUB2 to use the
built-in GNU Privacy Guard (GPG) verification observed the following
error on boot :

alloc magic is broken at [addr]: [value] Aborted.

Consequently, the boot failed. The GRUB2 built-in GPG verification has
been modified to no longer free the same memory twice. As a result,
the mentioned error no longer occurs. (BZ#1167977)

* Previously, the system sometimes did not recover after terminating
unexpectedly and failed to reboot. To fix this problem, the GRUB2
packages now enforce file synchronization when creating the GRUB2
configuration file, which ensures that the required configuration
files are written to disk. As a result, the system now reboots
successfully after crashing. (BZ#1212114)

* Previously, if an unconfigured network driver instance was selected
and configured when the GRUB2 bootloader was loaded on a different
instance, GRUB2 did not receive notifications of the Address
Resolution Protocol (ARP) replies. Consequently, GRUB2 failed with the
following error message :

error: timeout: could not resolve hardware address.

With this update, GRUB2 selects the network driver instance from which
it was loaded. As a result, ARP packets are processed correctly.
(BZ#1257475)

In addition, this update adds the following enhancement :

* Sorting of GRUB2 boot menu has been improved. GRUB2 now uses the
rpmdevtools package to sort available kernels and the configuration
file is being generated correctly with the most recent kernel version
listed at the top. (BZ#1124074)

All grub2 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002293.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d451fcf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected grub2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5281");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-efi-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"grub2-2.02-0.29.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"grub2-efi-2.02-0.29.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"grub2-efi-modules-2.02-0.29.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"grub2-tools-2.02-0.29.el7.centos")) flag++;


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
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2 / grub2-efi / grub2-efi-modules / grub2-tools");
}
