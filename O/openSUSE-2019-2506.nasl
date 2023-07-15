#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2506.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131060);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12207", "CVE-2019-11135", "CVE-2019-18420", "CVE-2019-18421", "CVE-2019-18424", "CVE-2019-18425");
  script_xref(name:"IAVB", value:"2019-B-0084-S");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2019-2506)");
  script_summary(english:"Check for the openSUSE-2019-2506 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the following issues :

  - CVE-2018-12207: Untrusted virtual machines on Intel CPUs
    could exploit a race condition in the Instruction Fetch
    Unit of the Intel CPU to cause a Machine Exception
    during Page Size Change, causing the CPU core to be
    non-functional. (bsc#1155945)

  - CVE-2019-11135: Aborting an asynchronous TSX operation
    on Intel CPUs with Transactional Memory support could be
    used to facilitate sidechannel information leaks out of
    microarchitectural buffers, similar to the previously
    described 'Microarchitectural Data Sampling' attack.
    (bsc#1152497).

  - CVE-2019-18425: 32-bit PV guest user mode could elevate
    its privileges to that of the guest kernel.
    (bsc#1154456).

  - CVE-2019-18421: A malicious PV guest administrator may
    have been able to escalate their privilege to that of
    the host. (bsc#1154458).

  - CVE-2019-18420: Malicious x86 PV guests may have caused
    a hypervisor crash, resulting in a Denial of Service
    (Dos). (bsc#1154448)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155945"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"xen-debugsource-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-devel-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-libs-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-libs-debuginfo-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-tools-domU-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-tools-domU-debuginfo-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-doc-html-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-libs-32bit-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-libs-32bit-debuginfo-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-tools-4.10.4_06-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.10.4_06-lp150.2.25.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-debugsource / xen-devel / xen-doc-html / xen-libs / etc");
}
