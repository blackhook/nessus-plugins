#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0841-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159042);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/17");

  script_cve_id("CVE-2022-23853", "CVE-2022-25255");

  script_name(english:"openSUSE 15 Security Update : libqt5-qtbase (openSUSE-SU-2022:0841-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0841-1 advisory.

  - The LSP (Language Server Protocol) plugin in KDE Kate before 21.12.2 and KTextEditor before 5.91.0 tries
    to execute the associated LSP server binary when opening a file of a given type. If this binary is absent
    from the PATH, it will try running the LSP server binary in the directory of the file that was just opened
    (due to a misunderstanding of the QProcess API, that was never intended). This can be an untrusted
    directory. (CVE-2022-23853)

  - In Qt 5.9.x through 5.15.x before 5.15.9 and 6.x before 6.2.4 on Linux and UNIX, QProcess could execute a
    binary from the current working directory when not found in the PATH. (CVE-2022-25255)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196501");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NIPE5FF5VKMSL2BZDJ46HDRCTHGR7IUG/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b85c0803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-25255");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5KmsSupport-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5KmsSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGLExtensions-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGLExtensions-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformHeaders-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-xdgdesktopportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'libQt5Bootstrap-devel-static-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Bootstrap-devel-static-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Concurrent-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Concurrent-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Concurrent5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Concurrent5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Core-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Core-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Core-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Core5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Core5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5DBus-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5DBus-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5DBus-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5DBus5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5DBus5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Gui-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Gui-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Gui-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Gui5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Gui5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5KmsSupport-devel-static-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5KmsSupport-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Network-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Network-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Network-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Network5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Network5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5OpenGL-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5OpenGL-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5OpenGL-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5OpenGL5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5OpenGL5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5OpenGLExtensions-devel-static-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5OpenGLExtensions-devel-static-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5PlatformHeaders-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5PlatformSupport-devel-static-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5PlatformSupport-devel-static-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5PlatformSupport-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5PrintSupport-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5PrintSupport-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5PrintSupport-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5PrintSupport5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5PrintSupport5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-mysql-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-mysql-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-postgresql-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-postgresql-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-sqlite-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-sqlite-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-unixODBC-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Sql5-unixODBC-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Test-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Test-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Test-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Test5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Test5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Widgets-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Widgets-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Widgets-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Widgets5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Widgets5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Xml-devel-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Xml-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Xml5-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libQt5Xml5-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libqt5-qtbase-common-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libqt5-qtbase-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libqt5-qtbase-examples-32bit-5.12.7-4.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libqt5-qtbase-examples-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libqt5-qtbase-platformtheme-gtk3-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libqt5-qtbase-platformtheme-xdgdesktopportal-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libqt5-qtbase-private-headers-devel-5.12.7-4.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libQt5Bootstrap-devel-static / libQt5Bootstrap-devel-static-32bit / etc');
}
