#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-799.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101349);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2017-10912", "CVE-2017-10913", "CVE-2017-10914", "CVE-2017-10915", "CVE-2017-10917", "CVE-2017-10918", "CVE-2017-10920", "CVE-2017-10921", "CVE-2017-10922", "CVE-2017-8309", "CVE-2017-9330");
  script_xref(name:"IAVB", value:"2017-B-0074-S");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2017-799)");
  script_summary(english:"Check for the openSUSE-2017-799 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes several issues.

These security issues were fixed :

  - CVE-2017-10912: Page transfer might have allowed PV
    guest to elevate privilege (XSA-217, bsc#1042882)

  - CVE-2017-10913 CVE-2017-10914: Races in the grant table
    unmap code allowed for informations leaks and
    potentially privilege escalation (XSA-218, bsc#1042893)

  - CVE-2017-10915: Insufficient reference counts during
    shadow emulation allowed a malicious pair of guest to
    elevate their privileges to the privileges that XEN runs
    under (XSA-219, bsc#1042915)

  - CVE-2017-10917: Missing NULL pointer check in event
    channel poll allows guests to DoS the host (XSA-221,
    bsc#1042924)

  - CVE-2017-10918: Stale P2M mappings due to insufficient
    error checking allowed malicious guest to leak
    information or elevate privileges (XSA-222, bsc#1042931)

  - CVE-2017-10920, CVE-2017-10921, CVE-2017-10922: Grant
    table operations mishandled reference counts allowing
    malicious guests to escape (XSA-224, bsc#1042938)

  - CVE-2017-9330: USB OHCI Emulation in qemu allowed local
    guest OS users to cause a denial of service (infinite
    loop) by leveraging an incorrect return value
    (bsc#1042160)

  - CVE-2017-8309: Memory leak in the audio/audio.c allowed
    remote attackers to cause a denial of service (memory
    consumption) by repeatedly starting and stopping audio
    capture (bsc#1037243)

  - PKRU and BND* leakage between vCPU-s might have leaked
    information to other guests (XSA-220, bsc#1042923)

These non-security issues were fixed :

  - bsc#1027519: Included various upstream patches 

  - bsc#1035642: Ensure that rpmbuild works

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042938"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/10");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"xen-debugsource-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-devel-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-libs-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-libs-debuginfo-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-tools-domU-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-tools-domU-debuginfo-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-doc-html-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-libs-32bit-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-tools-4.7.2_06-11.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.7.2_06-11.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen-debugsource / xen-devel / xen-libs-32bit / xen-libs / etc");
}
