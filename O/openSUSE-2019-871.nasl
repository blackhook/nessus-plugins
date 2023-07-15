#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-871.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123362);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-14526");

  script_name(english:"openSUSE Security Update : wpa_supplicant (openSUSE-2019-871)");
  script_summary(english:"Check for the openSUSE-2019-871 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wpa_supplicant provides the following fixes :

This security issues was fixe :

  - CVE-2018-14526: Under certain conditions, the integrity
    of EAPOL-Key messages was not checked, leading to a
    decryption oracle. An attacker within range of the
    Access Point and client could have abused the
    vulnerability to recover sensitive information
    (bsc#1104205)

These non-security issues were fixed :

  - Fix reading private key passwords from the configuration
    file. (bsc#1099835)

  - Enable PWD as EAP method. This allows for password-based
    authentication, which is easier to setup than most of
    the other methods, and is used by the Eduroam network.
    (bsc#1109209)

  - compile eapol_test binary to allow testing via radius
    proxy and server (note: this does not match
    CONFIG_EAPOL_TEST which sets -Werror and activates an
    assert call inside the code of wpa_supplicant)
    (bsc#1111873), (fate#326725)

  - Enabled timestamps in log file when being invoked by
    systemd service file (bsc#1080798).

  - Fixes the default file permissions of the debug log file
    to more sane values, i.e. it is no longer world-readable
    (bsc#1098854).

  - Open the debug log file with O_CLOEXEC, which will
    prevent file descriptor leaking to child processes
    (bsc#1098854).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111873"
  );
  # https://features.opensuse.org/326725
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wpa_supplicant packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-gui-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"wpa_supplicant-2.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wpa_supplicant-debuginfo-2.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wpa_supplicant-debugsource-2.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wpa_supplicant-gui-2.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wpa_supplicant-gui-debuginfo-2.6-lp150.3.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wpa_supplicant / wpa_supplicant-debuginfo / etc");
}
