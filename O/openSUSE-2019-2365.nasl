#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2365.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130160);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2019-14250", "CVE-2019-15847");

  script_name(english:"openSUSE Security Update : gcc7 (openSUSE-2019-2365)");
  script_summary(english:"Check for the openSUSE-2019-2365 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gcc7 to r275405 fixes the following issues :

Security issues fixed :

  - CVE-2019-14250: Fixed an integer overflow in binutils
    (bsc#1142649).

  - CVE-2019-15847: Fixed an optimization in the POWER9
    backend of gcc that could reduce the entropy of the
    random number generator (bsc#1149145).

Non-security issue fixed :

  - Move Live Patching technology stack from kGraft to
    upstream klp (bsc#1071995, fate#323487).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/323487"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gcc7 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-ada");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-ada-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-ada-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-c++-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-fortran-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-fortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-go-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-go-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-obj-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-obj-c++-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-obj-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-objc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc7-objc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada7-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcilkrts5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcilkrts5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcilkrts5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcilkrts5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo11-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-devel-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-devel-gcc7-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/23");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"cpp7-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cpp7-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-ada-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-ada-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-c++-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-c++-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-debugsource-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-fortran-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-fortran-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-go-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-go-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-info-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-locale-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-obj-c++-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-obj-c++-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-objc-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gcc7-objc-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libada7-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libada7-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libasan4-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libasan4-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcilkrts5-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcilkrts5-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgfortran4-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgfortran4-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgo11-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgo11-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libobjc4-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libobjc4-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libstdc++6-devel-gcc7-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libubsan0-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libubsan0-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"gcc7-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"gcc7-ada-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"gcc7-c++-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"gcc7-go-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"gcc7-obj-c++-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"gcc7-objc-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libada7-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libada7-32bit-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libasan4-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcilkrts5-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgfortran4-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgo11-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgo11-32bit-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libobjc4-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libobjc4-32bit-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libubsan0-32bit-7.4.1+r275405-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.4.1+r275405-lp150.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp7 / cpp7-debuginfo / gcc7-32bit / gcc7 / gcc7-ada-32bit / etc");
}
