#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-406.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(147779);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/17");

  script_cve_id("CVE-2021-27218", "CVE-2021-27219");

  script_name(english:"openSUSE Security Update : glib2 (openSUSE-2021-406)");
  script_summary(english:"Check for the openSUSE-2021-406 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for glib2 fixes the following issues :

  - CVE-2021-27218: g_byte_array_new_take takes a gsize as
    length but stores in a guint, this patch will refuse if
    the length is larger than guint. (bsc#1182328)

  - CVE-2021-27219: g_memdup takes a guint as parameter and
    sometimes leads into an integer overflow, so add a
    g_memdup2 function which uses gsize to replace it.
    (bsc#1182362)

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182362"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected glib2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gio-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tools-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tools-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-fam-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-fam-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-fam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"gio-branding-upstream-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glib2-debugsource-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glib2-devel-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glib2-devel-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glib2-devel-static-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glib2-lang-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glib2-tests-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glib2-tests-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glib2-tools-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glib2-tools-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgio-2_0-0-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgio-2_0-0-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgio-fam-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgio-fam-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libglib-2_0-0-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libglib-2_0-0-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgmodule-2_0-0-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgmodule-2_0-0-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgobject-2_0-0-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgobject-2_0-0-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgthread-2_0-0-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgthread-2_0-0-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glib2-devel-32bit-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glib2-devel-32bit-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glib2-tools-32bit-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glib2-tools-32bit-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgio-2_0-0-32bit-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgio-fam-32bit-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgio-fam-32bit-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libglib-2_0-0-32bit-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-debuginfo-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.62.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-debuginfo-2.62.6-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gio-branding-upstream / glib2-debugsource / glib2-devel / etc");
}
