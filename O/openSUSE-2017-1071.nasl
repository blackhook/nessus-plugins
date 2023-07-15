#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1071.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103291);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-14316", "CVE-2017-14317", "CVE-2017-14318", "CVE-2017-14319");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2017-1071)");
  script_summary(english:"Check for the openSUSE-2017-1071 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes several issues.

These security issues were fixed :

  - CVE-2017-14316: Missing bound check in function
    `alloc_heap_pages` for an internal array allowed
    attackers using crafted hypercalls to execute arbitrary
    code within Xen (XSA-231, bsc#1056278)

  - CVE-2017-14318: The function __gnttab_cache_flush missed
    a check for grant tables, allowing a malicious guest to
    crash the host or for x86 PV guests to potentially
    escalate privileges (XSA-232, bsc#1056280)

  - CVE-2017-14317: A race in cxenstored may have cause a
    double-free allowind for DoS of the xenstored daemon
    (XSA-233, bsc#1056281).

  - CVE-2017-14319: An error while handling grant mappings
    allowed malicious or buggy x86 PV guest to escalate its
    privileges or crash the hypervisor (XSA-234,
    bsc#1056282).

These non-security issues were fixed :

  - bsc#1057358: Fixed boot into SUSE Linux Enterprise 12.3
    with secure boot

  - bsc#1055695: Fixed restoring updates for HVM guests for
    ballooned domUs

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057358"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/18");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"xen-4.9.0_12-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-debugsource-4.9.0_12-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-devel-4.9.0_12-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-doc-html-4.9.0_12-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-4.9.0_12-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-debuginfo-4.9.0_12-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-4.9.0_12-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-debuginfo-4.9.0_12-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-4.9.0_12-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-debuginfo-4.9.0_12-7.1") ) flag++;

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
