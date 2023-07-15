#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-37.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106066);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-7542");

  script_name(english:"openSUSE Security Update : gwenhywfar (openSUSE-2018-37)");
  script_summary(english:"Check for the openSUSE-2018-37 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gwenhywfar fixes the following issues :

Security issue fixed :

  - CVE-2015-7542: Make use of the system's default trusted
    CAs. Also remove the upstream provided ca-bundle.crt
    file and require ca-certificates so the /etc/ssl/certs
    directory is populated (bsc#958331).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958331"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gwenhywfar packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gwenhywfar-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gwenhywfar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gwenhywfar-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gwenhywfar-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gwenhywfar-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgwengui-gtk2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgwengui-gtk2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgwengui-qt4-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgwengui-qt4-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgwenhywfar60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgwenhywfar60-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgwenhywfar60-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgwenhywfar60-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"gwenhywfar-debugsource-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gwenhywfar-devel-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gwenhywfar-lang-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gwenhywfar-tools-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gwenhywfar-tools-debuginfo-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgwengui-gtk2-0-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgwengui-gtk2-0-debuginfo-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgwengui-qt4-0-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgwengui-qt4-0-debuginfo-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgwenhywfar60-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgwenhywfar60-debuginfo-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgwenhywfar60-plugins-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgwenhywfar60-plugins-debuginfo-4.9.0beta-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gwenhywfar-debugsource-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gwenhywfar-devel-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gwenhywfar-lang-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gwenhywfar-tools-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gwenhywfar-tools-debuginfo-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgwengui-gtk2-0-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgwengui-gtk2-0-debuginfo-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgwengui-qt4-0-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgwengui-qt4-0-debuginfo-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgwenhywfar60-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgwenhywfar60-debuginfo-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgwenhywfar60-plugins-4.9.0beta-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgwenhywfar60-plugins-debuginfo-4.9.0beta-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gwenhywfar-debugsource / gwenhywfar-devel / gwenhywfar-lang / etc");
}
