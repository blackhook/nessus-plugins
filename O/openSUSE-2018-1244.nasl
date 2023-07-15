#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1244.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118380);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : pam_pkcs11 (openSUSE-2018-1244)");
  script_summary(english:"Check for the openSUSE-2018-1244 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pam_pkcs11 provides the following fixes :

Security issues fixed (bsc#1105012) :

  - Fixed a logic bug in pampkcs11.c, leading to an
    authentication replay vulnerability

  - Fixed a stack-based buffer overflow in opensshmapper.c

  - Make sure memory is properly cleaned before invoking
    free()

Other changes :

  - Add a systemd service file. (bsc#1049219)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105012"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pam_pkcs11 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_pkcs11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_pkcs11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_pkcs11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_pkcs11-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/25");
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

if ( rpm_check(release:"SUSE42.3", reference:"pam_pkcs11-0.6.8-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pam_pkcs11-debuginfo-0.6.8-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pam_pkcs11-debugsource-0.6.8-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pam_pkcs11-32bit-0.6.8-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pam_pkcs11-debuginfo-32bit-0.6.8-13.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam_pkcs11 / pam_pkcs11-32bit / pam_pkcs11-debuginfo / etc");
}
