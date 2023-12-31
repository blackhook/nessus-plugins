#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-3174.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49668);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-2959", "CVE-2010-3081", "CVE-2010-3301");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2010:0654-1)");
  script_summary(english:"Check for the kernel-3174 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update of the openSUSE 11.1 kernel fixes 3 critical
security issues.

Following security bugs were fixed: CVE-2010-3301: Mismatch between
32bit and 64bit register usage in the system call entry path could be
used by local attackers to gain root privileges. This problem only
affects x86_64 kernels.

CVE-2010-3081: Incorrect buffer handling in the biarch-compat buffer
handling could be used by local attackers to gain root privileges.
This problem affects foremost x86_64, or potentially other biarch
platforms, like PowerPC and S390x.

CVE-2010-2959: Integer overflow in net/can/bcm.c in the Controller
Area Network (CAN) implementation in the Linux kernel allowed
attackers to execute arbitrary code or cause a denial of service
(system crash) via crafted CAN traffic."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2010-09/msg00041.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-base-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-extra-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-base-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-extra-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-base-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-extra-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-source-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-syms-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-base-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-extra-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-vanilla-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-base-2.6.27.48-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-extra-2.6.27.48-0.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-extra / etc");
}
