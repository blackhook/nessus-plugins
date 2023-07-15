#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-160.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145435);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/26");

  script_name(english:"openSUSE Security Update : stunnel (openSUSE-2021-160)");
  script_summary(english:"Check for the openSUSE-2021-160 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for stunnel fixes the following issues :

Security issue fixed :

  - The 'redirect' option was fixed to properly handle
    'verifyChain = yes' (bsc#1177580).

Non-security issues fixed :

  - Fix startup problem of the stunnel daemon (bsc#1178533)

  - update to 5.57 :

  - Security bugfixes

  - New features

  - New securityLevel configuration file option.

  - Support for modern PostgreSQL clients

  - TLS 1.3 configuration updated for better compatibility.

  - Bugfixes

  - Fixed a transfer() loop bug.

  - Fixed memory leaks on configuration reloading errors.

  - DH/ECDH initialization restored for client sections.

  - Delay startup with systemd until network is online.

  - A number of testing framework fixes and improvements.

  - update to 5.56 :

  - Various text files converted to Markdown format.

  - Support for realpath(3) implementations incompatible
    with POSIX.1-2008, such as 4.4BSD or Solaris.

  - Support for engines without PRNG seeding methods (thx to
    Petr Mikhalitsyn).

  - Retry unsuccessful port binding on configuration file
    reload.

  - Thread safety fixes in SSL_SESSION object handling.

  - Terminate clients on exit in the FORK threading model.

  - Fixup stunnel.conf handling :

  - Remove old static openSUSE provided stunnel.conf.

  - Use upstream stunnel.conf and tailor it for openSUSE
    using sed.

  - Don't show README.openSUSE when installing.

  - enable /etc/stunnel/conf.d

  - re-enable openssl.cnf

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178533"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected stunnel packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:stunnel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:stunnel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:stunnel-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");
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

if ( rpm_check(release:"SUSE15.2", reference:"stunnel-5.57-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"stunnel-debuginfo-5.57-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"stunnel-debugsource-5.57-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "stunnel / stunnel-debuginfo / stunnel-debugsource");
}
