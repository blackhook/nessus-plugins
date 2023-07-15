#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-853.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111634);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-3005", "CVE-2018-3055", "CVE-2018-3085", "CVE-2018-3086", "CVE-2018-3087", "CVE-2018-3088", "CVE-2018-3089", "CVE-2018-3090", "CVE-2018-3091");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2018-853)");
  script_summary(english:"Check for the openSUSE-2018-853 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox to version 5.2.16 fixes the following
issues :

The following security vulnerabilities were fixed (boo#1101667) :

  - CVE-2018-3005: Fixed an easily exploitable vulnerability
    that allowed unauthenticated attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks of
    this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of
    Oracle VM VirtualBox.

  - CVE-2018-3055: Fixed an easily exploitable vulnerability
    that allowed unauthenticated attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks
    require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle VM
    VirtualBox, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle VM
    VirtualBox and unauthorized read access to a subset of
    Oracle VM VirtualBox accessible data.

  - CVE-2018-3085: Fixed an easily exploitable vulnerability
    that allowed unauthenticated attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks
    require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle VM
    VirtualBox, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in unauthorized creation, deletion or
    modification access to critical data or all Oracle VM
    VirtualBox accessible data as well as unauthorized read
    access to a subset of Oracle VM VirtualBox accessible
    data and unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle VM
    VirtualBox.

  - CVE-2018-3086: Fixed an easily exploitable vulnerability
    that allowed unauthenticated attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks
    require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle VM
    VirtualBox, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox.

  - CVE-2018-3087: Fixed an easily exploitable vulnerability
    that allowed unauthenticated attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks
    require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle VM
    VirtualBox, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox.

  - CVE-2018-3088: Fixed an easily exploitable vulnerability
    allows unauthenticated attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks
    require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle VM
    VirtualBox, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox.

  - CVE-2018-3089: Fixed an easily exploitable vulnerability
    allows unauthenticated attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks
    require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle VM
    VirtualBox, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox.

  - CVE-2018-3090: Fixed an easily exploitable vulnerability
    allows unauthenticated attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks
    require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle VM
    VirtualBox, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox.

  - CVE-2018-3091: Fixed an easily exploitable vulnerability
    allows unauthenticated attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks
    require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle VM
    VirtualBox, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in unauthorized access to critical data or
    complete access to all Oracle VM VirtualBox accessible
    data.

The following bugs were fixed :

  - OVF: case insensitive comparison of manifest attribute
    values, to improve compatibility"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101667"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-debuginfo-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debuginfo-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debugsource-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-devel-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-desktop-icons-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-5.2.16_k4.12.14_lp150.12.7-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-debuginfo-5.2.16_k4.12.14_lp150.12.7-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-source-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-debuginfo-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-debuginfo-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-5.2.16_k4.12.14_lp150.12.7-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-debuginfo-5.2.16_k4.12.14_lp150.12.7-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-source-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-debuginfo-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-vnc-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-5.2.16-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-debuginfo-5.2.16-lp150.4.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-virtualbox / python3-virtualbox-debuginfo / virtualbox / etc");
}
