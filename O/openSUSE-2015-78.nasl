#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-78.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81030);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/22");

  script_cve_id("CVE-2015-0311");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/04");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-SU-2015:0150-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Adobe Flash Player was updated to 11.2.202.440 (bsc#914463, APSA15-01,
CVE-2015-0311).

More information can be found on
https://helpx.adobe.com/security/products/flash-player/apsa15-01.html

An update of flashplayer (executable binary) for i386 is currently not
available. Disabled!");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914463");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsa15-01.html");
  script_set_attribute(attribute:"see_also", value:"https://lists.opensuse.org/opensuse-updates/2015-01/msg00082.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected flash-player packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player ByteArray UncompressViaZlibVariant Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"flash-player-11.2.202.440-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-gnome-11.2.202.440-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-kde4-11.2.202.440-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-11.2.202.440-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-gnome-11.2.202.440-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-kde4-11.2.202.440-2.29.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player / flash-player-gnome / flash-player-kde4");
}
