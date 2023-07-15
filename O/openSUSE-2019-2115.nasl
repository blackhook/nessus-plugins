#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2115.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(128669);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-9511",
    "CVE-2019-9512",
    "CVE-2019-9513",
    "CVE-2019-9514",
    "CVE-2019-9515",
    "CVE-2019-9516",
    "CVE-2019-9517",
    "CVE-2019-9518"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"openSUSE Security Update : nodejs8 (openSUSE-2019-2115) (0-Length Headers Leak) (Data Dribble) (Empty Frames Flood) (Internal Data Buffering) (Ping Flood) (Reset Flood) (Resource Loop) (Settings Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for nodejs8 to version 8.16.1 fixes the following issues :

Security issues fixed :

  - CVE-2019-9511: Fixed HTTP/2 implementations that are
    vulnerable to window size manipulation and stream
    prioritization manipulation, potentially leading to a
    denial of service (bsc#1146091).

  - CVE-2019-9512: Fixed HTTP/2 flood using PING frames
    results in unbounded memory growth (bsc#1146099).

  - CVE-2019-9513: Fixed HTTP/2 implementation that is
    vulnerable to resource loops, potentially leading to a
    denial of service. (bsc#1146094).

  - CVE-2019-9514: Fixed HTTP/2 implementation that is
    vulnerable to a reset flood, potentially leading to a
    denial of service (bsc#1146095).

  - CVE-2019-9515: Fixed HTTP/2 flood using SETTINGS frames
    results in unbounded memory growth (bsc#1146100).

  - CVE-2019-9516: Fixed HTTP/2 implementation that is
    vulnerable to a header leak, potentially leading to a
    denial of service (bsc#1146090).

  - CVE-2019-9517: Fixed HTTP/2 implementations that are
    vulnerable to unconstrained interal data buffering
    (bsc#1146097).

  - CVE-2019-9518: Fixed HTTP/2 implementation that is
    vulnerable to a flood of empty frames, potentially
    leading to a denial of service (bsc#1146093).

Bug fixes :

  - Fixed that npm resolves its default config file like in
    all other versions, as /etc/nodejs/npmrc (bsc#1144919).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146100");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs8 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs8-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"nodejs8-8.16.1-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nodejs8-debuginfo-8.16.1-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nodejs8-debugsource-8.16.1-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nodejs8-devel-8.16.1-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"npm8-8.16.1-lp151.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs8 / nodejs8-debuginfo / nodejs8-debugsource / nodejs8-devel / etc");
}
