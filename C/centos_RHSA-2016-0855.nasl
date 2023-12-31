#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0855 and 
# CentOS Errata and Security Advisory 2016:0855 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91170);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-5313", "CVE-2013-4312", "CVE-2014-7842", "CVE-2014-8134", "CVE-2015-5156", "CVE-2015-7509", "CVE-2015-8215", "CVE-2015-8324", "CVE-2015-8543", "CVE-2016-3841");
  script_xref(name:"RHSA", value:"2016:0855");

  script_name(english:"CentOS 6 : kernel (CESA-2016:0855)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* It was found that reporting emulation failures to user space could
lead to either a local (CVE-2014-7842) or a L2->L1 (CVE-2010-5313)
denial of service. In the case of a local denial of service, an
attacker must have access to the MMIO area or be able to access an I/O
port. Please note that on certain systems, HPET is mapped to userspace
as part of vdso (vvar) and thus an unprivileged user may generate MMIO
transactions (and enter the emulator) this way. (CVE-2010-5313,
CVE-2014-7842, Moderate)

* It was found that the Linux kernel did not properly account file
descriptors passed over the unix socket against the process limit. A
local user could use this flaw to exhaust all available memory on the
system. (CVE-2013-4312, Moderate)

* A buffer overflow flaw was found in the way the Linux kernel's
virtio-net subsystem handled certain fraglists when the GRO (Generic
Receive Offload) functionality was enabled in a bridged network
configuration. An attacker on the local network could potentially use
this flaw to crash the system, or, although unlikely, elevate their
privileges on the system. (CVE-2015-5156, Moderate)

* It was found that the Linux kernel's IPv6 network stack did not
properly validate the value of the MTU variable when it was set. A
remote attacker could potentially use this flaw to disrupt a target
system's networking (packet loss) by setting an invalid MTU value, for
example, via a NetworkManager daemon that is processing router
advertisement packets running on the target system. (CVE-2015-8215,
Moderate)

* A NULL pointer dereference flaw was found in the way the Linux
kernel's network subsystem handled socket creation with an invalid
protocol identifier. A local user could use this flaw to crash the
system. (CVE-2015-8543, Moderate)

* It was found that the espfix functionality does not work for 32-bit
KVM paravirtualized guests. A local, unprivileged guest user could
potentially use this flaw to leak kernel stack addresses.
(CVE-2014-8134, Low)

* A flaw was found in the way the Linux kernel's ext4 file system
driver handled non-journal file systems with an orphan list. An
attacker with physical access to the system could use this flaw to
crash the system or, although unlikely, escalate their privileges on
the system. (CVE-2015-7509, Low)

* A NULL pointer dereference flaw was found in the way the Linux
kernel's ext4 file system driver handled certain corrupted file system
images. An attacker with physical access to the system could use this
flaw to crash the system. (CVE-2015-8324, Low)

Red Hat would like to thank Nadav Amit for reporting CVE-2010-5313 and
CVE-2014-7842, Andy Lutomirski for reporting CVE-2014-8134, and
Dmitriy Monakhov (OpenVZ) for reporting CVE-2015-8324. The
CVE-2015-5156 issue was discovered by Jason Wang (Red Hat).

Additional Changes :

* Refer to Red Hat Enterprise Linux 6.8 Release Notes for information
on new kernel features and known issues, and Red Hat Enterprise Linux
Technical Notes for information on device driver updates, important
changes to external kernel parameters, notable bug fixes, and
technology previews. Both of these documents are linked to in the
References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-May/002855.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae358ae1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3841");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-642.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-642.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-642.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-642.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-642.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-642.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-642.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-642.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-642.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-642.el6")) flag++;


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
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / kernel-debug-devel / etc");
}
