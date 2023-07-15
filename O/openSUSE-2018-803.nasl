#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-803.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111565);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-11806", "CVE-2018-12891", "CVE-2018-12892", "CVE-2018-12893", "CVE-2018-3665");
  script_xref(name:"IAVB", value:"2018-B-0094-S");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2018-803)");
  script_summary(english:"Check for the openSUSE-2018-803 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the following issues :

Security issues fixed :

  - CVE-2018-3665: Fix Lazy FP Save/Restore issue (XSA-267)
    (bsc#1095242).

  - CVE-2018-12891: Fix possible Denial of Service (DoS) via
    certain PV MMU operations that affect the entire host
    (XSA-264) (bsc#1097521).

  - CVE-2018-12892: Fix libxl to honour the readonly flag on
    HVM emulated SCSI disks (XSA-266) (bsc#1097523).

  - CVE-2018-12893: Fix crash/Denial of Service (DoS) via
    safety check (XSA-265) (bsc#1097522).

  - CVE-2018-11806: Fix heap buffer overflow while
    reassembling fragmented datagrams (bsc#1096224).

Bug fixes :

  - bsc#1027519: Add upstream patches from January.

  - bsc#1087289: Fix xen scheduler crash.

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097523"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"xen-4.9.2_08-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-debugsource-4.9.2_08-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-devel-4.9.2_08-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-doc-html-4.9.2_08-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-4.9.2_08-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-debuginfo-4.9.2_08-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-4.9.2_08-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-debuginfo-4.9.2_08-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-4.9.2_08-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-debuginfo-4.9.2_08-25.2") ) flag++;

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
