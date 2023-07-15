#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1341.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105231);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-9157");

  script_name(english:"openSUSE Security Update : graphviz (openSUSE-2017-1341)");
  script_summary(english:"Check for the openSUSE-2017-1341 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for graphviz fixes the following issues :

Security issue fixed :

  - CVE-2014-9157: Fix format string vulnerability
    (boo#908426)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908426"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected graphviz packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-guile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gvedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gvedit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gvedit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-smyrna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-smyrna-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-smyrna-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
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

if ( rpm_check(release:"SUSE42.2", reference:"graphviz-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-debuginfo-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-debugsource-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-devel-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-gd-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-gd-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-gnome-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-gnome-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-guile-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-guile-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-gvedit-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-gvedit-debuginfo-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-gvedit-debugsource-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-java-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-java-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-lua-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-lua-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-perl-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-perl-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-php-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-php-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-plugins-debugsource-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-python-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-python-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-ruby-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-ruby-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-tcl-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"graphviz-tcl-debuginfo-2.38.0-4.5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"graphviz-smyrna-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"graphviz-smyrna-debuginfo-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"graphviz-smyrna-debugsource-2.38.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-2.38.0-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-debuginfo-2.38.0-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-debugsource-2.38.0-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-devel-2.38.0-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-gd-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-gd-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-gnome-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-gnome-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-guile-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-guile-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-gvedit-2.38.0-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-gvedit-debuginfo-2.38.0-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-gvedit-debugsource-2.38.0-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-java-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-java-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-lua-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-lua-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-perl-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-perl-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-php-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-php-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-plugins-debugsource-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-python-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-python-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-ruby-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-ruby-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-tcl-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"graphviz-tcl-debuginfo-2.38.0-9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"graphviz-smyrna-2.38.0-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"graphviz-smyrna-debuginfo-2.38.0-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"graphviz-smyrna-debugsource-2.38.0-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphviz-gvedit / graphviz-gvedit-debuginfo / etc");
}
