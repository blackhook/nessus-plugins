#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-300.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(146715);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/22");

  script_name(english:"openSUSE Security Update : mumble (openSUSE-2021-300)");
  script_summary(english:"Check for the openSUSE-2021-300 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mumble fixes the following issues :

mumble was updated to 1.3.4 :

  - Fix use of outdated (non-existent) notification icon
    names

  - Fix Security vulnerability caused by allowing non
    http/https URL schemes in public server list
    (boo#1182123)

  - Server: Fix Exit status for actions like --version or
    --supw

  - Fix packet loss & audio artifacts caused by OCB2 XEX*
    mitigation

  - update apparmor profiles to get warning free again on
    15.2

  - use abstractions for ssl files

  - allow inet dgram sockets as mumble can also work via udp

  - allow netlink socket (probably for dbus)

  - properly allow lsb_release again

  - add support for optional local include

  - start murmurd directly as user mumble-server it gets rid
    of the dac_override/setgid/setuid/chown permissions

Update to upstream version 1.3.3

Client :

  - Fixed: Chatbox invisble (zero height) (#4388)

  - Fixed: Handling of invalid packet sizes (#4394)

  - Fixed: Race-condition leading to loss of shortcuts
    (#4430)

  - Fixed: Link in About dialog is now clickable again
    (#4454)

  - Fixed: Sizing issues in ACL-Editor (#4455)

  - Improved: PulseAudio now always samples at 48 kHz
    (#4449)

Server :

  - Fixed: Crash due to problems when using PostgreSQL
    (#4370)

  - Fixed: Handling of invalid package sizes (#4392)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182123"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected mumble packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mumble");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mumble-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mumble-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mumble-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mumble-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mumble-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mumble-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"mumble-1.3.4-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mumble-debuginfo-1.3.4-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mumble-debugsource-1.3.4-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mumble-server-1.3.4-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mumble-server-debuginfo-1.3.4-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"mumble-32bit-1.3.4-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"mumble-32bit-debuginfo-1.3.4-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mumble / mumble-debuginfo / mumble-debugsource / mumble-server / etc");
}
