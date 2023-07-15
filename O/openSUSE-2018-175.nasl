#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-175.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106893);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-2131");

  script_name(english:"openSUSE Security Update : rrdtool (openSUSE-2018-175)");
  script_summary(english:"Check for the openSUSE-2018-175 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for rrdtool fixes the following issues :

  - CVE-2013-2131: Added check to the imginfo format to
    prevent crash or exploit (boo#828003)

  - Fixed an infinite loop and crashing with pango
    [boo#1080251]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=828003"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rrdtool packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lua-rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lua-rrdtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rrdtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rrdtool-cached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rrdtool-cached-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rrdtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rrdtool-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rrdtool-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-rrdtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcl-rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcl-rrdtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
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

if ( rpm_check(release:"SUSE42.3", reference:"lua-rrdtool-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lua-rrdtool-debuginfo-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rrdtool-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rrdtool-debuginfo-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rrdtool-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rrdtool-cached-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rrdtool-cached-debuginfo-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rrdtool-debuginfo-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rrdtool-debugsource-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rrdtool-devel-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ruby-rrdtool-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ruby-rrdtool-debuginfo-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tcl-rrdtool-1.4.7-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tcl-rrdtool-debuginfo-1.4.7-26.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lua-rrdtool / lua-rrdtool-debuginfo / python-rrdtool / etc");
}
