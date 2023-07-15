#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-756.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101191);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-9604");

  script_name(english:"openSUSE Security Update : kdepim / messagelib (openSUSE-2017-756)");
  script_summary(english:"Check for the openSUSE-2017-756 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kdepim and messagelib fixes the following issues :

  - CVE-2017-9604: The kmail 'send later' function does not
    have 'sign/encryption' action ensured. (boo#1044210)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044210"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdepim / messagelib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:akonadi_resources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:akonadi_resources-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:akregator5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:akregator5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:blogilo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:blogilo5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kaddressbook5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kaddressbook5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kalarm5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kalarm5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kmail5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kmail5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:knotes5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:knotes5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kontact5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kontact5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:korganizer5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:korganizer5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ktnef5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ktnef5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:messagelib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:messagelib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:messagelib-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:messagelib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/03");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"akonadi_resources-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"akonadi_resources-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"akregator5-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"akregator5-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"blogilo5-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"blogilo5-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kaddressbook5-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kaddressbook5-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kalarm5-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kalarm5-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdepim-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdepim-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdepim-debugsource-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kmail5-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kmail5-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"knotes5-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"knotes5-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kontact5-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kontact5-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"korganizer5-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"korganizer5-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ktnef5-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ktnef5-debuginfo-16.08.2-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"messagelib-16.08.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"messagelib-debuginfo-16.08.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"messagelib-debugsource-16.08.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"messagelib-devel-16.08.2-2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "akonadi_resources / akonadi_resources-debuginfo / akregator5 / etc");
}
