#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-973.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102811);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-9263", "CVE-2017-9265");

  script_name(english:"openSUSE Security Update : openvswitch (openSUSE-2017-973)");
  script_summary(english:"Check for the openSUSE-2017-973 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openvswitch fixes the following issues :

  - CVE-2017-9263: OpenFlow role status message can cause a
    call to abort() leading to application crash
    (bsc#1041470)

  - CVE-2017-9265: Buffer over-read while parsing message
    could lead to crash or maybe arbitrary code execution
    (bsc#1041447)

  - Do not restart the ovs-vswitchd and ovsdb-server
    services on package updates (bsc#1002734)

  - Do not restart the ovs-vswitchd, ovsdb-server and
    openvswitch services on package removals. This
    facilitates potential future package moves but also
    preserves connectivity when the package is removed
    (bsc#1050896)

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050896"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openvswitch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/29");
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

if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-debuginfo-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-debugsource-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-devel-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-central-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-central-debuginfo-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-common-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-common-debuginfo-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-docker-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-host-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-host-debuginfo-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-vtep-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-vtep-debuginfo-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-pki-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-test-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-test-debuginfo-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-vtep-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-vtep-debuginfo-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-openvswitch-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-openvswitch-test-2.7.0-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvswitch / openvswitch-debuginfo / openvswitch-debugsource / etc");
}
