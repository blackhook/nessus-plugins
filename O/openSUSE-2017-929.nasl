#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-929.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102509);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-8831");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-929)");
  script_summary(english:"Check for the openSUSE-2017-929 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2017-1000111: Fixed a race condition in net-packet
    code that could be exploited to cause out-of-bounds
    memory access (bsc#1052365).

  - CVE-2017-1000112: Fixed a race condition in net-packet
    code that could have been exploited by unprivileged
    users to gain root access. (bsc#1052311).

  - CVE-2017-8831: The saa7164_bus_get function in
    drivers/media/pci/saa7164/saa7164-bus.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds array access) or possibly have
    unspecified other impact by changing a certain
    sequence-number value, aka a 'double fetch'
    vulnerability (bnc#1037994).

The following non-security bugs were fixed :

  - IB/hfi1: Wait for QSFP modules to initialize
    (bsc#1019151).

  - bcache: force trigger gc (bsc#1038078).

  - bcache: only recovery I/O error for writethrough mode
    (bsc#1043652).

  - block: do not allow updates through sysfs until
    registration completes (bsc#1047027).

  - ibmvnic: Check for transport event on driver resume
    (bsc#1051556, bsc#1052709).

  - ibmvnic: Initialize SCRQ's during login renegotiation
    (bsc#1052223).

  - ibmvnic: Report rx buffer return codes as netdev_dbg
    (bsc#1052794).

  - iommu/amd: Fix schedule-while-atomic BUG in
    initialization code (bsc1052533).

  - libnvdimm, pmem: fix a NULL pointer BUG in
    nd_pmem_notify (bsc#1023175).

  - libnvdimm: fix badblock range handling of ARS range
    (bsc#1023175).

  - qeth: fix L3 next-hop im xmit qeth hdr (bnc#1052773,
    LTC#157374).

  - scsi_devinfo: fixup string compare (bsc#1037404).

  - scsi_dh_alua: suppress errors from unsupported devices
    (bsc#1038792).

  - vfs: fix missing inode_get_dev sites (bsc#1052049).

  - x86/dmi: Switch dmi_remap() from ioremap() to
    ioremap_cache() (bsc#1051399)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052794"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.79-18.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.79-18.26.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.79-18.26.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.79-18.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.79-18.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.79-18.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.79-18.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.79-18.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.79-18.26.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.79-18.26.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
