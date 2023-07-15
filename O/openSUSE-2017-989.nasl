#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-989.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102944);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7435", "CVE-2017-7436", "CVE-2017-9269");

  script_name(english:"openSUSE Security Update : libzypp (openSUSE-2017-989)");
  script_summary(english:"Check for the openSUSE-2017-989 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Software Update Stack was updated to receive fixes and
enhancements.

libzypp :

  - CVE-2017-7435, CVE-2017-7436, CVE-2017-9269: Fix GPG
    check workflows, mainly for unsigned repositories and
    packages. (bsc#1045735, bsc#1038984)

  - Fix gpg-pubkey release (creation time) computation.
    (bsc#1036659)

  - Update lsof blacklist. (bsc#1046417)

  - Re-probe on refresh if the repository type changes.
    (bsc#1048315)

  - Propagate proper error code to DownloadProgressReport.
    (bsc#1047785)

  - Allow to trigger an appdata refresh unconditionally.
    (bsc#1009745)

  - Support custom repo variables defined in
    /etc/zypp/vars.d.

yast2-pkg-bindings :

  - Do not crash when the repository URL is not defined.
    (bsc#1043218)

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048315"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libzypp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-pkg-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-pkg-bindings-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-pkg-bindings-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libzypp-16.15.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzypp-debuginfo-16.15.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzypp-debugsource-16.15.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzypp-devel-16.15.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"yast2-pkg-bindings-3.2.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"yast2-pkg-bindings-debuginfo-3.2.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"yast2-pkg-bindings-debugsource-3.2.4-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzypp / libzypp-debuginfo / libzypp-debugsource / libzypp-devel / etc");
}
