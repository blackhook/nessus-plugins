#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-200.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122300);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-20748", "CVE-2018-20749", "CVE-2018-20750");

  script_name(english:"openSUSE Security Update : LibVNCServer (openSUSE-2019-200)");
  script_summary(english:"Check for the openSUSE-2019-200 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for LibVNCServer fixes the following issues: &#9; Security
issues fixed :

  - CVE-2018-20749: Fixed a heap out of bounds write
    vulnerability in rfbserver.c (bsc#1123828)

  - CVE-2018-20750: Fixed a heap out of bounds write
    vulnerability in rfbserver.c (bsc#1123832)

  - CVE-2018-20748: Fixed multiple heap out-of-bound writes
    in VNC client code (bsc#1123823) 

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123832"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected LibVNCServer packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:LibVNCServer-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:LibVNCServer-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncserver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncserver0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:linuxvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:linuxvnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"LibVNCServer-debugsource-0.9.9-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"LibVNCServer-devel-0.9.9-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvncclient0-0.9.9-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvncclient0-debuginfo-0.9.9-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvncserver0-0.9.9-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvncserver0-debuginfo-0.9.9-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"linuxvnc-0.9.9-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"linuxvnc-debuginfo-0.9.9-16.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibVNCServer-debugsource / LibVNCServer-devel / libvncclient0 / etc");
}
