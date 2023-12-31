#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-163.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133490);
  script_version("1.2");
  script_cvs_date("Date: 2020/02/07");

  script_cve_id("CVE-2018-11243", "CVE-2019-1010048", "CVE-2019-14296", "CVE-2019-20021", "CVE-2019-20053");

  script_name(english:"openSUSE Security Update : upx (openSUSE-2020-163)");
  script_summary(english:"Check for the openSUSE-2020-163 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for upx to version 3.96 fixes the following issues :

  - CVE-2019-1010048: Fixed a denial of service in
    PackLinuxElf32::PackLinuxElf32help1() (boo#1141777).

  - CVE-2019-14296: Fixed a denial of service in canUnpack()
    (boo#1143839).

  - CVE-2019-20021: Fixed a heap-based buffer over-read in
    canUnpack() (boo#1159833).

  - CVE-2019-20053: Fixed a denial of service in canUnpack()
    (boo#1159920).

  - CVE-2018-11243: Fixed a denial of service in
    PackLinuxElf64::unpack() (boo#1094138).

  - Update to version 3.96

  - Bug fixes: [CVE-2019-1010048, boo#1141777]
    [CVE-2019-14296, boo#1143839] [CVE-2019-20021,
    boo#1159833] [CVE-2019-20053, boo#1159920]
    [CVE-2018-11243 partially - ticket 206 ONLY,
    boo#1094138]

  - Update to version 3.95

  - Flag --force-pie when ET_DYN main program is not marked
    as DF_1_PIE

  - Better compatibility with varying layout of address
    space on Linux

  - Support for 4 PT_LOAD layout in ELF generated by
    binutils-2.31

  - bug fixes, particularly better diagnosis of malformed
    input

  - bug fixes - see https://github.com/upx/upx/milestone/4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/upx/upx/milestone/4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected upx packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:upx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:upx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:upx-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/05");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"upx-3.96-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"upx-debuginfo-3.96-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"upx-debugsource-3.96-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "upx / upx-debuginfo / upx-debugsource");
}
