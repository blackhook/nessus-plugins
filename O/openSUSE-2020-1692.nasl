#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1692.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141528);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/21");

  script_cve_id("CVE-2020-13844");

  script_name(english:"openSUSE Security Update : gcc10 / nvptx-tools (openSUSE-2020-1692)");
  script_summary(english:"Check for the openSUSE-2020-1692 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gcc10, nvptx-tools fixes the following issues :

This update provides the GCC10 compiler suite and runtime libraries.

The base SUSE Linux Enterprise libraries libgcc_s1, libstdc++6 are
replaced by the gcc10 variants.

The new compiler variants are available with '-10' suffix, you can
specify them via :

&#9;CC=gcc-10 &#9;CXX=g++-10

or similar commands.

For a detailed changelog check out
https://gcc.gnu.org/gcc-10/changes.html

Changes in nvptx-tools :

  - Enable build on aarch64 This update was imported from
    the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://gcc.gnu.org/gcc-10/changes.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected gcc10 / nvptx-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-nvptx-gcc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-nvptx-gcc10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-nvptx-gcc10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-nvptx-newlib10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-ada");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-ada-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-ada-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-c++-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-d-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-d-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-fortran-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-fortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-go-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-go-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-obj-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-obj-c++-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-obj-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-objc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc10-objc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada10-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdruntime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdruntime1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdruntime1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdruntime1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo16-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgphobos1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgphobos1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgphobos1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgphobos1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libobjc4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-devel-gcc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-devel-gcc10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-pp-gcc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-pp-gcc10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nvptx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nvptx-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nvptx-tools-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");
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

if ( rpm_check(release:"SUSE15.1", reference:"cpp10-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cpp10-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cross-nvptx-gcc10-10.2.1+git583-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cross-nvptx-gcc10-debuginfo-10.2.1+git583-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cross-nvptx-gcc10-debugsource-10.2.1+git583-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cross-nvptx-newlib10-devel-10.2.1+git583-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-ada-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-ada-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-ada-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-c++-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-c++-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-c++-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-d-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-d-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-d-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-debugsource-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-fortran-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-fortran-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-fortran-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-go-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-go-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-go-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-info-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-locale-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-obj-c++-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-obj-c++-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-obj-c++-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-objc-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-objc-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gcc10-objc-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libada10-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libada10-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libada10-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libada10-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasan6-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasan6-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasan6-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasan6-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libatomic1-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libatomic1-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libatomic1-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libatomic1-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgcc_s1-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgcc_s1-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgcc_s1-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgcc_s1-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgdruntime1-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgdruntime1-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgdruntime1-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgdruntime1-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfortran5-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfortran5-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfortran5-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfortran5-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgo16-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgo16-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgo16-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgo16-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgomp1-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgomp1-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgomp1-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgomp1-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgphobos1-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgphobos1-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgphobos1-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgphobos1-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libitm1-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libitm1-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libitm1-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libitm1-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"liblsan0-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"liblsan0-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libobjc4-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libobjc4-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libobjc4-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libobjc4-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libquadmath0-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libquadmath0-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libquadmath0-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libquadmath0-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-devel-gcc10-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-devel-gcc10-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-locale-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-pp-gcc10-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libstdc++6-pp-gcc10-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libtsan0-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libtsan0-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libubsan1-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libubsan1-32bit-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libubsan1-32bit-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libubsan1-debuginfo-10.2.1+git583-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nvptx-tools-1.0-lp151.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nvptx-tools-debuginfo-1.0-lp151.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nvptx-tools-debugsource-1.0-lp151.3.3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cross-nvptx-gcc10 / cross-nvptx-gcc10-debuginfo / etc");
}
