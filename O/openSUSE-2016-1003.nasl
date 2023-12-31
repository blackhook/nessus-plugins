#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1003.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93063);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-6128", "CVE-2016-6132", "CVE-2016-6161", "CVE-2016-6207", "CVE-2016-6214");

  script_name(english:"openSUSE Security Update : gd (openSUSE-2016-1003)");
  script_summary(english:"Check for the openSUSE-2016-1003 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gd fixes the following issues :

  - CVE-2016-6214: Buffer over-read issue when parsing
    crafted TGA file [bsc#991436]

  - CVE-2016-6132: read out-of-bands was found in the
    parsing of TGA files using libgd [bsc#987577]

  - CVE-2016-6128: Invalid color index not properly handled
    [bsc#991710]

  - CVE-2016-6207: Integer overflow error within
    _gdContributionsAlloc() [bsc#991622]

  - CVE-2016-6161: global out of bounds read when encoding
    gif from malformed input withgd2togif [bsc#988032]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991710"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgd3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgd3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgd3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgd3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"gd-2.1.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gd-debuginfo-2.1.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gd-debugsource-2.1.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gd-devel-2.1.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgd3-2.1.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgd3-debuginfo-2.1.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgd3-32bit-2.1.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgd3-debuginfo-32bit-2.1.0-7.11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gd / gd-debuginfo / gd-debugsource / gd-devel / libgd3 / etc");
}
