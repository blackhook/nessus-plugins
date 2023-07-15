#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-514.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(148384);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-3308", "CVE-2021-28687");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2021-514)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for xen fixes the following issues :

  - CVE-2021-3308: VUL-0: xen: IRQ vector leak on x86
    (bsc#1181254, XSA-360)

  - CVE-2021-28687: HVM soft-reset crashes toolstack
    (bsc#1183072, XSA-368)

  - L3: conring size for XEN HV's with huge memory to small.
    Inital Xen logs cut (bsc#1177204)

  - L3: XEN domU crashed on resume when using the xl unpause
    command (bsc#1182576)

  - L3: xen: no needsreboot flag set (bsc#1180690)

  - kdump of HVM fails, soft-reset not handled by libxl
    (bsc#1179148)

  - openQA job causes libvirtd to dump core when running
    kdump inside domain (bsc#1181989)

  - Upstream bug fixes (bsc#1027519)

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183072");
  script_set_attribute(attribute:"solution", value:
"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3308");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/08");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-xendomains-wait-disk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"xen-debugsource-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xen-devel-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xen-libs-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xen-libs-debuginfo-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xen-tools-domU-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xen-tools-domU-debuginfo-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xen-tools-xendomains-wait-disk-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"xen-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"xen-doc-html-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"xen-libs-32bit-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"xen-libs-32bit-debuginfo-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"xen-tools-4.13.2_08-lp152.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.13.2_08-lp152.2.24.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-debugsource / xen-devel / xen-doc-html / xen-libs / etc");
}
