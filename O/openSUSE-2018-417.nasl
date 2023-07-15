#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-417.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109541);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1084");
  script_xref(name:"IAVA", value:"2018-A-0127");

  script_name(english:"openSUSE Security Update : corosync (openSUSE-2018-417)");
  script_summary(english:"Check for the openSUSE-2018-417 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for corosync fixes the following issues :

  - CVE-2018-1084: Integer overflow in
    totemcrypto:authenticate_nss_2_3() could lead to command
    execution (bsc#1089346)

  - Providing an empty uid or gid results in coroparse
    adding uid 0. (bsc#1066585)

  - Fix a problem with configuration file incompatibilities
    that was causing corosync to not work after upgrading
    from SLE-11-SP4-HA to SLE-12/15-HA. (bsc#1083561)

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089346"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected corosync packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:corosync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:corosync-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:corosync-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:corosync-testagents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:corosync-testagents-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcorosync-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcorosync4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcorosync4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcorosync4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcorosync4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/03");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"corosync-2.3.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"corosync-debuginfo-2.3.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"corosync-debugsource-2.3.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"corosync-testagents-2.3.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"corosync-testagents-debuginfo-2.3.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcorosync-devel-2.3.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcorosync4-2.3.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcorosync4-debuginfo-2.3.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libcorosync4-32bit-2.3.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libcorosync4-debuginfo-32bit-2.3.6-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "corosync / corosync-debuginfo / corosync-debugsource / etc");
}
