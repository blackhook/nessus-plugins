#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-693.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(136882);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-10722",
    "CVE-2020-10723",
    "CVE-2020-10724",
    "CVE-2020-10725",
    "CVE-2020-10726"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"openSUSE Security Update : dpdk (openSUSE-2020-693)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for dpdk fixes the following issues :

Security issues fixed :

  - CVE-2020-10722: Fixed an integer overflow in
    vhost_user_set_log_base() (bsc#1171477).

  - CVE-2020-10723: Fixed an integer truncation in
    vhost_user_check_and_alloc_queue_pair() (bsc#1171477).

  - CVE-2020-10724: Fixed a missing inputs validation in
    Vhost-crypto (bsc#1171477).

  - CVE-2020-10725: Fixed a segfault caused by invalid
    virtio descriptors sent from a malicious guest
    (bsc#1171477).

  - CVE-2020-10726: Fixed a denial-of-service caused by
    VHOST_USER_GET_INFLIGHT_FD message flooding
    (bsc#1171477).

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171477");
  script_set_attribute(attribute:"solution", value:
"Update the affected dpdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10723");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdpdk-18_11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdpdk-18_11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"dpdk-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-debuginfo-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-debugsource-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-devel-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-devel-debuginfo-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-examples-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-examples-debuginfo-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-kmp-default-18.11.3_k4.12.14_lp151.28.48-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-kmp-default-debuginfo-18.11.3_k4.12.14_lp151.28.48-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-tools-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dpdk-tools-debuginfo-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdpdk-18_11-18.11.3-lp151.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdpdk-18_11-debuginfo-18.11.3-lp151.3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dpdk / dpdk-debuginfo / dpdk-debugsource / dpdk-devel / etc");
}
