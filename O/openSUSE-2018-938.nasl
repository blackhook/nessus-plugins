#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-938.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112143);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5715", "CVE-2018-0739", "CVE-2018-2676", "CVE-2018-2685", "CVE-2018-2686", "CVE-2018-2687", "CVE-2018-2688", "CVE-2018-2689", "CVE-2018-2690", "CVE-2018-2693", "CVE-2018-2694", "CVE-2018-2698", "CVE-2018-2830", "CVE-2018-2831", "CVE-2018-2835", "CVE-2018-2836", "CVE-2018-2837", "CVE-2018-2842", "CVE-2018-2843", "CVE-2018-2844", "CVE-2018-2845", "CVE-2018-2860", "CVE-2018-3005", "CVE-2018-3055", "CVE-2018-3085", "CVE-2018-3086", "CVE-2018-3087", "CVE-2018-3088", "CVE-2018-3089", "CVE-2018-3090", "CVE-2018-3091");

  script_name(english:"openSUSE Security Update : kbuild / virtualbox (openSUSE-2018-938) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-938 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kbuild, virtualbox fixes the following issues :

kbuild changes :

  - Update to version 0.1.9998svn3110

  - Do not assume glibc glob internals

  - Support GLIBC glob interface version 2

  - Fix build failure (boo#1079838)

  - Fix build with GCC7 (boo#1039375)

  - Fix build by disabling vboxvideo_drv.so

virtualbox security fixes (boo#1101667, boo#1076372) :

  - CVE-2018-3005

  - CVE-2018-3055

  - CVE-2018-3085

  - CVE-2018-3086

  - CVE-2018-3087

  - CVE-2018-3088

  - CVE-2018-3089

  - CVE-2018-3090

  - CVE-2018-3091

  - CVE-2018-2694

  - CVE-2018-2698

  - CVE-2018-2685

  - CVE-2018-2686

  - CVE-2018-2687

  - CVE-2018-2688

  - CVE-2018-2689

  - CVE-2018-2690

  - CVE-2018-2676

  - CVE-2018-2693

  - CVE-2017-5715

virtualbox other changes :

  - Version bump to 5.2.16

  - Use %(?linux_make_arch) when building kernel modules
    (boo#1098050)

  - Fixed vboxguestconfig.sh script

  - Update warning regarding the security hole in USB
    passthrough. (boo#1097248)

  - Fixed include for build with Qt 5.11 (boo#1093731)

  - You can find a detailed list of changes
    [here](https://www.virtualbox.org/wiki/Changelog#v16)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.virtualbox.org/wiki/Changelog#v16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kbuild / virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kbuild-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kbuild-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"kbuild-0.1.9998svn3110-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kbuild-debuginfo-0.1.9998svn3110-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kbuild-debugsource-0.1.9998svn3110-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-desktop-icons-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-source-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-source-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"python-virtualbox-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"python-virtualbox-debuginfo-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-debuginfo-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-debugsource-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-devel-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-guest-kmp-default-5.2.18_k4.4.143_65-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-guest-kmp-default-debuginfo-5.2.18_k4.4.143_65-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-guest-tools-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-guest-tools-debuginfo-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-guest-x11-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-guest-x11-debuginfo-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-host-kmp-default-5.2.18_k4.4.143_65-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-host-kmp-default-debuginfo-5.2.18_k4.4.143_65-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-qt-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-qt-debuginfo-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-vnc-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-websrv-5.2.18-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"virtualbox-websrv-debuginfo-5.2.18-56.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kbuild / kbuild-debuginfo / kbuild-debugsource / python-virtualbox / etc");
}
