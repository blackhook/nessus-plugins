#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-724.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103163);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-6706");

  script_name(english:"openSUSE Security Update : unrar (openSUSE-2017-724)");
  script_summary(english:"Check for the openSUSE-2017-724 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for unrar to version 5.5 fixes the following issues :

Version 5.5.5

  - CVE-2012-6706: fixes VMSF_DELTA memory corruption
    (boo#1045315) see
    https://bugs.chromium.org/p/project-zero/issues/detail?i
    d=1286&can=1&q=unrar&desc=2

Version 5.5.1

  - Based on RAR 5.50 beta1

  - Added extraction support for .LZ archives created by
    Lzip compressor.

  - Modern TAR tools can store high precision file times,
    lengthy file names and large file sizes in special PAX
    extended headers inside of TAR archive. Now WinRAR
    supports such PAX headers and uses them when extracting
    TAR archives.

  - unrar no longer fails to unpack files in ZIP archives
    compressed with XZ algorithm and encrypted with AES

Version 5.4.5.

  - Based on final RAR 5.40.

  - If RAR recovery volumes (.rev files) are present in the
    same folder as usual RAR volumes, archive test command
    verifies .rev contents after completing testing .rar
    files. If you wish to test only .rev files without
    checking .rar volumes, you can run: `unrar t
    arcname.part1.rev`.

  - If -p switch is used without optional <pwd> parameter, a
    password can be also set with file redirection or pipe.

  - unrar treats 'arcname.partN' as 'arcname.partN.rar' if
    'arcname.partN' does not exist and 'arcname.part#.rar'
    exists. For example, it is allowed to run: `unrar x
    arcname.part01` to start extraction from
    'arcname.part01.rar'."
  );
  # https://bugs.chromium.org/p/project-zero/issues/detail?id=1286&can=1&q=unrar&desc=2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21e268eb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045315"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unrar packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunrar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunrar5_5_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunrar5_5_5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unrar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unrar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unrar-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libunrar-devel-5.5.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libunrar5_5_5-5.5.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libunrar5_5_5-debuginfo-5.5.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"unrar-5.5.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"unrar-debuginfo-5.5.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"unrar-debugsource-5.5.5-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libunrar-devel / libunrar5_5_5 / libunrar5_5_5-debuginfo / unrar / etc");
}
