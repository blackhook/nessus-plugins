#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1223.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104245);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11671");

  script_name(english:"openSUSE Security Update : gcc48 (openSUSE-2017-1223)");
  script_summary(english:"Check for the openSUSE-2017-1223 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gcc48 fixes the following issues :

Security issues fixed :

  - A new option -fstack-clash-protection is now offered,
    which mitigates the stack clash type of attacks.
    [bnc#1039513] Future maintenance releases of packages
    will be built with this option.

  - CVE-2017-11671: Fixed rdrand/rdseed code generation
    issue [bsc#1050947]

Bugs fixed :

  - Enable LFS support in 32bit libgcov.a. [bsc#1044016]

  - Bump libffi version in libffi.pc to 3.0.11.

  - Fix libffi issue for armv7l. [bsc#988274]

  - Properly diagnose missing -fsanitize=address support on
    ppc64le. [bnc#1028744]

  - Backport patch for PR65612. [bnc#1022062]

  - Fixed DR#1288. [bnc#1011348]

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988274"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gcc48 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-aarch64-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-armv6hl-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-armv7hl-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-i386-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ia64-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64le-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390x-gcc48-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-ada");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-ada-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-ada-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-fortran-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-fortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-gij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-gij-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-gij-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-gij-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-obj-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-obj-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-objc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-objc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc48-testresults");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada48-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada48-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi4-gcc48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi4-gcc48-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi4-gcc48-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi4-gcc48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi48-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi48-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi48-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj48-jar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj_bc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcj_bc1-gcc48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++48-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++48-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"cpp48-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cpp48-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-ada-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-ada-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-c++-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-c++-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-debugsource-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-fortran-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-fortran-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-gij-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-gij-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-info-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-java-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-java-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-locale-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-obj-c++-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-obj-c++-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-objc-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-objc-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gcc48-testresults-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libada48-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libada48-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libasan0-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libasan0-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libffi4-gcc48-4.8.5-23.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libffi4-gcc48-debuginfo-4.8.5-23.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libffi48-debugsource-4.8.5-23.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libffi48-devel-4.8.5-23.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcj48-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcj48-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcj48-debugsource-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcj48-devel-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcj48-devel-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcj48-jar-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcj_bc1-gcc48-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libobjc4-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libobjc4-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libstdc++48-devel-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-aarch64-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-armv6hl-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-armv7hl-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-i386-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-ia64-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-ppc-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-ppc64-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-ppc64le-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-s390-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"cross-s390x-gcc48-icecream-backend-4.8.5-23.3.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"gcc48-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"gcc48-ada-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"gcc48-fortran-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"gcc48-gij-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"gcc48-gij-debuginfo-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"gcc48-objc-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libada48-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libada48-32bit-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libasan0-32bit-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libffi4-gcc48-32bit-4.8.5-23.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libffi4-gcc48-32bit-debuginfo-4.8.5-23.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libffi48-devel-32bit-4.8.5-23.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgcj48-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgcj48-debuginfo-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgcj48-devel-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgcj48-devel-debuginfo-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libobjc4-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libobjc4-32bit-debuginfo-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libstdc++48-devel-32bit-4.8.5-23.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cpp48-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cpp48-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-ada-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-ada-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-c++-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-c++-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-debugsource-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-fortran-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-fortran-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-gij-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-gij-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-info-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-java-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-java-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-locale-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-obj-c++-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-obj-c++-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-objc-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-objc-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gcc48-testresults-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libada48-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libada48-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libasan0-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libasan0-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libffi4-gcc48-4.8.5-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libffi4-gcc48-debuginfo-4.8.5-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libffi48-debugsource-4.8.5-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libffi48-devel-4.8.5-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgcj48-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgcj48-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgcj48-debugsource-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgcj48-devel-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgcj48-devel-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgcj48-jar-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgcj_bc1-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libobjc4-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libobjc4-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libstdc++48-devel-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-aarch64-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-armv6hl-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-armv7hl-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-i386-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-ia64-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-ppc-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-ppc64-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-ppc64le-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-s390-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-s390x-gcc48-icecream-backend-4.8.5-26.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gcc48-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gcc48-ada-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gcc48-fortran-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gcc48-gij-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gcc48-gij-debuginfo-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gcc48-objc-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libada48-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libada48-32bit-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libasan0-32bit-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libffi4-gcc48-32bit-4.8.5-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libffi4-gcc48-32bit-debuginfo-4.8.5-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libffi48-devel-32bit-4.8.5-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgcj48-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgcj48-debuginfo-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgcj48-devel-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgcj48-devel-debuginfo-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libobjc4-32bit-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libobjc4-32bit-debuginfo-4.8.5-26.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libstdc++48-devel-32bit-4.8.5-26.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc48-testresults / cpp48 / cpp48-debuginfo / gcc48 / gcc48-ada / etc");
}
