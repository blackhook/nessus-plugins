#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-472.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74697);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-2738");

  script_name(english:"openSUSE Security Update : gnome-terminal (openSUSE-SU-2012:0933-1)");
  script_summary(english:"Check for the openSUSE-2012-472 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Add vte-CVE-2012-2738.patch: fix potential DoS through malicious
escape sequences. Fix bnc#772761, CVE-2012-2738."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-08/msg00003.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnome-terminal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glade3-catalog-vte");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvte9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvte9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-vte");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-vte-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vte2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vte2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vte2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vte2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vte2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"glade3-catalog-vte-0.28.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libvte9-0.28.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libvte9-debuginfo-0.28.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-vte-0.28.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-vte-debuginfo-0.28.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"vte2-debugsource-0.28.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"vte2-devel-0.28.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"vte2-lang-0.28.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"vte2-tools-0.28.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"vte2-tools-debuginfo-0.28.2-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-terminal");
}
