#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xen-201107-4929.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76049);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-1898");

  script_name(english:"openSUSE Security Update : xen-201107 (openSUSE-SU-2011:0941-1)");
  script_summary(english:"Check for the xen-201107-4929 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security / Collective Update for Xen

Xen :

  - bnc#702025 - VUL-0: xen: VT-d (PCI passthrough) MSI trap
    injection (CVE-2011-1898)

  - bnc#703924 - update block-npiv scripts to support BFA
    HBA

  - bnc#689954 - L3: Live migrations fail when guest
    crashes: domain_crash_sync called from entry.S

  - bnc#693472 - Bridge hangs cause redundant ring failures
    in SLE 11 SP1 HAE + XEN

  - bnc#582265 - xen-scsi.ko not supported

  - bnc#670465 - When connecting to Xen guest through
    vncviewer mouse tracking is off.

  - bnc#684305 - on_crash is being ignored with kdump now
    working in HVM

vm-install :

  - bnc#692625 - virt-manager has problems to install guest
    from multiple CD"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=582265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=684297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=684305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=692625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=693472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=702025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=703924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-08/msg00034.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen-201107 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vm-install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"vm-install-0.4.31-0.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-debugsource-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-devel-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-doc-html-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-doc-pdf-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-default-4.0.2_52_k2.6.37.6_0.7-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-default-debuginfo-4.0.2_52_k2.6.37.6_0.7-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-desktop-4.0.2_52_k2.6.37.6_0.7-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-desktop-debuginfo-4.0.2_52_k2.6.37.6_0.7-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-pae-4.0.2_52_k2.6.37.6_0.7-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-pae-debuginfo-4.0.2_52_k2.6.37.6_0.7-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-libs-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-libs-debuginfo-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-debuginfo-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-domU-4.0.2_52-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-domU-debuginfo-4.0.2_52-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
