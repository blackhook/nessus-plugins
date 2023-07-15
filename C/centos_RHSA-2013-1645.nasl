#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1645 and 
# CentOS Errata and Security Advisory 2013:1645 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79170);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-6542", "CVE-2012-6545", "CVE-2013-0343", "CVE-2013-1928", "CVE-2013-1929", "CVE-2013-2164", "CVE-2013-2234", "CVE-2013-2851", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-3231", "CVE-2013-4345", "CVE-2013-4387", "CVE-2013-4591", "CVE-2013-4592");
  script_bugtraq_id(58795, 58906, 58908, 58989, 58991, 59390, 60375, 60409, 60874, 62042, 62043, 62049, 62696, 62740, 63790, 63791);
  script_xref(name:"RHSA", value:"2013:1645");

  script_name(english:"CentOS 6 : kernel (CESA-2013:1645)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, address
several hundred bugs, and add numerous enhancements are now available
as part of the ongoing support and maintenance of Red Hat Enterprise
Linux version 6. This is the fifth regular update.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the way the Linux kernel's IPv6 implementation
handled certain UDP packets when the UDP Fragmentation Offload (UFO)
feature was enabled. A remote attacker could use this flaw to crash
the system or, potentially, escalate their privileges on the system.
(CVE-2013-4387, Important)

* A flaw was found in the way the Linux kernel handled the creation of
temporary IPv6 addresses. If the IPv6 privacy extension was enabled
(/proc/sys/net/ipv6/conf/eth0/use_tempaddr set to '2'), an attacker on
the local network could disable IPv6 temporary address generation,
leading to a potential information disclosure. (CVE-2013-0343,
Moderate)

* A flaw was found in the way the Linux kernel handled HID (Human
Interface Device) reports with an out-of-bounds Report ID. An attacker
with physical access to the system could use this flaw to crash the
system or, potentially, escalate their privileges on the system.
(CVE-2013-2888, Moderate)

* An off-by-one flaw was found in the way the ANSI CPRNG
implementation in the Linux kernel processed non-block size aligned
requests. This could lead to random numbers being generated with less
bits of entropy than expected when ANSI CPRNG was used.
(CVE-2013-4345, Moderate)

* It was found that the fix for CVE-2012-2375 released via
RHSA-2012:1580 accidentally removed a check for small-sized result
buffers. A local, unprivileged user with access to an NFSv4 mount with
ACL support could use this flaw to crash the system or, potentially,
escalate their privileges on the system . (CVE-2013-4591, Moderate)

* A flaw was found in the way IOMMU memory mappings were handled when
moving memory slots. A malicious user on a KVM host who has the
ability to assign a device to a guest could use this flaw to crash the
host. (CVE-2013-4592, Moderate)

* Heap-based buffer overflow flaws were found in the way the Zeroplus
and Pantherlord/GreenAsia game controllers handled HID reports. An
attacker with physical access to the system could use these flaws to
crash the system or, potentially, escalate their privileges on the
system. (CVE-2013-2889, CVE-2013-2892, Moderate)

* Two information leak flaws were found in the logical link control
(LLC) implementation in the Linux kernel. A local, unprivileged user
could use these flaws to leak kernel stack memory to user space.
(CVE-2012-6542, CVE-2013-3231, Low)

* A heap-based buffer overflow in the way the tg3 Ethernet driver
parsed the vital product data (VPD) of devices could allow an attacker
with physical access to a system to cause a denial of service or,
potentially, escalate their privileges. (CVE-2013-1929, Low)

* Information leak flaws in the Linux kernel could allow a privileged,
local user to leak kernel memory to user space. (CVE-2012-6545,
CVE-2013-1928, CVE-2013-2164, CVE-2013-2234, Low)

* A format string flaw was found in the Linux kernel's block layer. A
privileged, local user could potentially use this flaw to escalate
their privileges to kernel level (ring0). (CVE-2013-2851, Low)

Red Hat would like to thank Stephan Mueller for reporting
CVE-2013-4345, and Kees Cook for reporting CVE-2013-2851.

This update also fixes several hundred bugs and adds enhancements.
Refer to the Red Hat Enterprise Linux 6.5 Release Notes for
information on the most significant of these changes, and the
Technical Notes for further information, both linked to in the
References.

All Red Hat Enterprise Linux 6 users are advised to install these
updated packages, which correct these issues, and fix the bugs and add
the enhancements noted in the Red Hat Enterprise Linux 6.5 Release
Notes and Technical Notes. The system must be rebooted for this update
to take effect."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000976.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5151f219"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2888");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-431.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-431.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-431.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-431.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-431.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-431.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-431.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-431.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-431.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-431.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / kernel-debug-devel / etc");
}
