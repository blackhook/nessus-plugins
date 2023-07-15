#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-283.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(146507);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/22");

  script_cve_id("CVE-2020-35498");

  script_name(english:"openSUSE Security Update : openvswitch (openSUSE-2021-283)");
  script_summary(english:"Check for the openSUSE-2021-283 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openvswitch fixes the following issues :

  - CVE-2020-35498: Fixed a denial of service related to the
    handling of Ethernet padding (bsc#1181742).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181742"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected openvswitch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenvswitch-2_13-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenvswitch-2_13-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libovn-20_03-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libovn-20_03-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-vtep-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn-central-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn-host-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovn-vtep-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ovs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libopenvswitch-2_13-0-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libopenvswitch-2_13-0-debuginfo-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libovn-20_03-0-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libovn-20_03-0-debuginfo-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-debuginfo-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-debugsource-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-devel-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-ipsec-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-pki-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-test-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-test-debuginfo-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-vtep-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvswitch-vtep-debuginfo-2.13.2-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-central-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-central-debuginfo-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-debuginfo-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-devel-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-docker-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-host-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-host-debuginfo-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-vtep-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ovn-vtep-debuginfo-20.03.1-lp152.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-ovs-2.13.2-lp152.3.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenvswitch-2_13-0 / libopenvswitch-2_13-0-debuginfo / etc");
}
