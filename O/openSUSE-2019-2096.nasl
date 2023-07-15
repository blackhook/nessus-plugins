#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2096.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128608);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2019-15757");

  script_name(english:"openSUSE Security Update : libmirage (openSUSE-2019-2096)");
  script_summary(english:"Check for the openSUSE-2019-2096 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libmirage fixes the following issues :

Security issues fixed :

  - CVE-2019-15757: Fixed NULL pointer dereference in the
    NRG parser (boo#1148728)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148728"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmirage packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-3_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-3_2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-libmirage-3_2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"libmirage-3_2-3.2.2-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-3_2-debuginfo-3.2.2-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-data-3.2.2-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-debuginfo-3.2.2-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-debugsource-3.2.2-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-devel-3.2.2-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-lang-3.2.2-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage11-3.2.2-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage11-debuginfo-3.2.2-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-libmirage-3_2-3.2.2-lp151.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmirage-3_2 / libmirage-3_2-debuginfo / libmirage-data / etc");
}
