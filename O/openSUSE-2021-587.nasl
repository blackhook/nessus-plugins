#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-587.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149564);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_name(english:"openSUSE Security Update : irssi (openSUSE-2021-587)");
  script_summary(english:"Check for the openSUSE-2021-587 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for irssi fixes the following issues :

irssi was updated to 1.2.3 (boo#1184848)

  - Fix the compilation of utf8proc (#1021)

  - Fix wrong call to free. By Zero King (#1076)

  - Fix a colour reset in true colour themes when
    encountering mIRC colours (#1059)

  - Fix memory leak on malformed CAP requests (#1120)

  - Fix an erroneous free of SASL data. Credit to Oss-Fuzz
    (#1128, #1130)

  - Re-set the TLS flag when reconnecting (#1027, #1134)

  - Fix the scrollback getting stuck after /clear (#1115,
    #1136)

  - Fix the input of Ctrl+C as the first character (#1153,
    #1154)

  - Fix crash on quit during unloading of modules on certain
    platforms (#1167)

  - Fix Irssi freezing input after Ctrl+Space on GLib >2.62
    (#1180, #1183)

  - Fix layout of IDCHANs. By Lauri Tirkkonen (#1197)

  - Fix crash when server got reconnected before it was
    properly connected (#1210, #1211)

  - Fix multiple identical active caps (#1249)

  - Minor help corrections (#1156, #1213, #1214, #1255)

  - Remove erroneous colour in the colorless theme. Reported
    and fixed by Nutchanon Wetchasit (#1220, #1221)

  - Fix invalid bounds calculation when editing the text
    entry. Found and fixed by Sergey Valentey (#1269)

  - Fix passing of negative size in buffer writes. Found and
    fixed by Sergey Valentey (#1270)

  - Fix Irssi freezing on slow hardware and fast DCC
    transfers (#159, #1271)

  - Fix compilation on Solaris (#1291)

  - Fix NULL pointer dereference when receiving broken JOIN
    record. Credit to Oss-Fuzz (#1292)

  - Fix crash on /connect to some sockets (#1239, #1298)

  - Fix Irssi rendering on Apple ARM. By Misty De M&eacute;o
    (#1267, #1268, #1290)

  - Fix crash on /lastlog with broken lines (#1281, #1299)

  - Fix memory leak when receiving bogus SASL authentication
    data. Found and fixed by Sergey Valentey (#1293)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184848"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected irssi packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
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

if ( rpm_check(release:"SUSE15.2", reference:"irssi-1.2.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"irssi-debuginfo-1.2.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"irssi-debugsource-1.2.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"irssi-devel-1.2.3-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irssi / irssi-debuginfo / irssi-debugsource / irssi-devel");
}
