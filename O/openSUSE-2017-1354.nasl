#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1354.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105239);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-14970");

  script_name(english:"openSUSE Security Update : openvswitch (openSUSE-2017-1354)");
  script_summary(english:"Check for the openSUSE-2017-1354 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openvswitch fixes the following issues :

Security issue fixed :

  - CVE-2017-14970: Add upstream patches to fix memory leaks
    (bsc#1061310).

Bug fixes :

  - Fix rpmlint warnings (bsc#1057357).

  - Add missing post/postun scriptlets for the ovn-common
    sub-package (bsc#1054094).

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061310"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openvswitch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-central-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-host-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-vtep-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-vtep-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-debuginfo-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-debugsource-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-devel-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-central-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-central-debuginfo-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-common-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-common-debuginfo-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-docker-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-host-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-host-debuginfo-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-vtep-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-vtep-debuginfo-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-pki-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-test-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-test-debuginfo-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-vtep-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-vtep-debuginfo-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-openvswitch-2.7.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-openvswitch-test-2.7.0-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvswitch / openvswitch-debuginfo / openvswitch-debugsource / etc");
}
