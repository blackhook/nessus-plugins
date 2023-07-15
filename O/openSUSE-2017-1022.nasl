#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1022.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103158);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-9603", "CVE-2017-10664", "CVE-2017-11434", "CVE-2017-12135", "CVE-2017-12136", "CVE-2017-12137", "CVE-2017-12855");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2017-1022)");
  script_summary(english:"Check for the openSUSE-2017-1022 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen to version 4.7.3 fixes several issues.

These security issues were fixed :

  - CVE-2017-12135: Unbounded recursion in grant table code
    allowed a malicious guest to crash the host or
    potentially escalate privileges/leak information
    (XSA-226, bsc#1051787).

  - CVE-2017-12137: Incorrectly-aligned updates to
    pagetables allowed for privilege escalation (XSA-227,
    bsc#1051788).

  - CVE-2017-12136: Race conditions with maptrack free list
    handling allows a malicious guest administrator to crash
    the host or escalate their privilege to that of the host
    (XSA-228, bsc#1051789).

  - CVE-2017-11434: The dhcp_decode function in
    slirp/bootp.c allowed local guest OS users to cause a
    denial of service (out-of-bounds read) via a crafted
    DHCP options string (bsc#1049578).

  - CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which
    allowed remote attackers to cause a denial of service
    (daemon crash) by disconnecting during a
    server-to-client reply attempt (bsc#1046637).

  - CVE-2017-12855: Premature clearing of GTF_writing /
    GTF_reading lead to potentially leaking sensitive
    information (XSA-230 CVE-2017-12855).

These non-security issues were fixed :

  - bsc#1055695: XEN: 11SP4 and 12SP3 HVM guests can not be
    restored after the save using xl stack 

  - bsc#1035231: Migration of HVM domU did not use
    superpages on destination dom0

  - bsc#1002573: Optimized LVM functions in block-dmmd
    block-dmmd

  - bsc#1037840: Xen-detect always showed HVM for PV guests

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055695"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"xen-debugsource-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-devel-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-libs-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-libs-debuginfo-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-tools-domU-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-tools-domU-debuginfo-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-doc-html-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-libs-32bit-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-tools-4.7.3_03-11.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.7.3_03-11.12.1") ) flag++;

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
