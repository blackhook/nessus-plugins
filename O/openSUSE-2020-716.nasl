#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-716.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136959);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/05");

  script_cve_id("CVE-2019-14250", "CVE-2019-15847");

  script_name(english:"openSUSE Security Update : gcc9 (openSUSE-2020-716)");
  script_summary(english:"Check for the openSUSE-2020-716 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update includes the GNU Compiler Collection 9.

This update ships the GCC 9.3 release.

A full changelog is provided by the GCC team on :

https://www.gnu.org/software/gcc/gcc-9/changes.html

The base system compiler libraries libgcc_s1, libstdc++6 and others
are now built by the gcc 9 packages.

To use it, install 'gcc9' or 'gcc9-c++' or other compiler brands and
use CC=gcc-9 / CXX=g++-9 during configuration for using it.

Security issues fixed :

  - CVE-2019-15847: Fixed a miscompilation in the POWER9
    back end, that optimized multiple calls of the
    __builtin_darn intrinsic into a single call.
    (bsc#1149145)

  - CVE-2019-14250: Fixed a heap overflow in the LTO linker.
    (bsc#1142649)

Non-security issues fixed :

  - Split out libstdc++ pretty-printers into a separate
    package supplementing gdb and the installed runtime.
    (bsc#1135254)

  - Fixed miscompilation for vector shift on s390.
    (bsc#1141897)

  - Includes a fix for Internal compiler error when building
    HepMC (bsc#1167898)

  - Includes fix for binutils version parsing

  - Add libstdc++6-pp provides and conflicts to avoid file
    conflicts with same minor version of libstdc++6-pp from
    gcc10.

  - Add gcc9 autodetect -g at lto link (bsc#1149995)

  - Install go tool buildid for bootstrapping go"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/SLE-6533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/SLE-6536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.gnu.org/software/gcc/gcc-9/changes.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gcc9 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-nvptx-gcc9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-nvptx-gcc9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-nvptx-gcc9-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-nvptx-newlib9-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-ada");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-ada-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-ada-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-c++-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-fortran-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-fortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-go-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-go-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc9-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada9-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo14-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo14-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo14-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-devel-gcc9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-devel-gcc9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-pp-gcc9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-pp-gcc9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/29");
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

if ( rpm_check(release:"SUSE15.1", reference:"cpp9-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cpp9-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cross-nvptx-gcc9-9.3.1+git1296-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cross-nvptx-gcc9-debuginfo-9.3.1+git1296-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cross-nvptx-gcc9-debugsource-9.3.1+git1296-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cross-nvptx-newlib9-devel-9.3.1+git1296-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-ada-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-ada-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-ada-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-c++-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-c++-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-c++-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-debugsource-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-fortran-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-fortran-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-fortran-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-go-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-go-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-go-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-info-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc9-locale-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libada9-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libada9-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libada9-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libada9-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasan5-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasan5-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasan5-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasan5-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libatomic1-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libatomic1-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libatomic1-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libatomic1-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgcc_s1-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgcc_s1-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgcc_s1-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgcc_s1-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfortran5-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfortran5-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfortran5-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfortran5-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgo14-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgo14-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgo14-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgo14-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgomp1-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgomp1-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgomp1-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgomp1-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libitm1-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libitm1-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libitm1-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libitm1-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"liblsan0-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"liblsan0-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libquadmath0-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libquadmath0-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libquadmath0-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libquadmath0-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-devel-gcc9-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-devel-gcc9-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-locale-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-pp-gcc9-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-pp-gcc9-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libtsan0-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libtsan0-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libubsan1-32bit-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libubsan1-32bit-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libubsan1-9.3.1+git1296-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libubsan1-debuginfo-9.3.1+git1296-lp151.2.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cross-nvptx-gcc9 / cross-nvptx-gcc9-debuginfo / etc");
}
