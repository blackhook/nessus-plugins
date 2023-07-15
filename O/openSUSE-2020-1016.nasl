#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1016.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138785);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/21");

  script_name(english:"openSUSE Security Update : mumble (openSUSE-2020-1016)");
  script_summary(english:"Check for the openSUSE-2020-1016 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mumble fixes the following issues :

mumble was updated 1.3.2 :

  - client: Fixed overlay not starting

Update to upstream version 1.3.1

  - Security

  - Fixed: Potential exploit in the OCB2 encryption (#4227)
    boo#1174041

  - ICE

  - Fixed: Added missing UserKDFIterations field to UserInfo
    => Prevents getRegistration() from failing with
    enumerator out of range error (#3835)

  - GRPC

  - Fixed: Segmentation fault during murmur shutdown (#3938)

  - Client

  - Fixed: Crash when using multiple monitors (#3756)

  - Fixed: Don't send empty message from clipboard via
    shortcut, if clipboard is empty (#3864)

  - Fixed: Talking indicator being able to freeze to
    indicate talking when self-muted (#4006)

  - Fixed: High CPU usage for update-check if update server
    not available (#4019)

  - Fixed: DBus getCurrentUrl returning empty string when
    not in root-channel (#4029)

  - Fixed: Small parts of whispering leaking out (#4051)

  - Fixed: Last audio frame of normal talking is sent to
    last whisper target (#4050)

  - Fixed: LAN-icon not found in ConnectDialog (#4058)

  - Improved: Set maximal vertical size for User Volume
    Adjustment dialog (#3801)

  - Improved: Don't send empty data to PulseAudio (#3316)

  - Improved: Use the SRV resolved port for UDP connections
    (#3820)

  - Improved: Manual Plugin UI (#3919)

  - Improved: Don't start Jack server by default (#3990)

  - Improved: Overlay doesn't hook into all other processes
    by default (#4041)

  - Improved: Wait longer before disconnecting from a server
    due to unanswered Ping-messages (#4123)

  - Server

  - Fixed: Possibility to circumvent max user-count in
    channel (#3880)

  - Fixed: Rate-limit implementation susceptible to
    time-underflow (#4004)

  - Fixed: OpenSSL error 140E0197 with Qt >= 5.12.2 (#4032)

  - Fixed: VersionCheck for SQL for when to use the WAL
    feature (#4163)

  - Fixed: Wrong database encoding that could lead to
    server-crash (#4220)

  - Fixed: DB crash due to primary key violation (now
    performs 'UPSERT' to avoid this) (#4105)

  - Improved: The fields in the Version ProtoBuf message are
    now size-restricted (#4101)

  - use the 'profile profilename /path/to/binary' syntax to
    make 'ps aufxZ' more readable"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174041"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"mumble-1.3.2-lp151.4.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mumble-debuginfo-1.3.2-lp151.4.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mumble-debugsource-1.3.2-lp151.4.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mumble-server-1.3.2-lp151.4.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mumble-server-debuginfo-1.3.2-lp151.4.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mumble-32bit-1.3.2-lp151.4.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mumble-32bit-debuginfo-1.3.2-lp151.4.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mumble-1.3.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mumble-debuginfo-1.3.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mumble-debugsource-1.3.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mumble-server-1.3.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mumble-server-debuginfo-1.3.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"mumble-32bit-1.3.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"mumble-32bit-debuginfo-1.3.2-lp152.2.3.1") ) flag++;

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
