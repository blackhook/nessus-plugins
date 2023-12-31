#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libcollection-devel-3829.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75573);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-4341");

  script_name(english:"openSUSE Security Update : libcollection-devel (openSUSE-SU-2011:0058-1)");
  script_summary(english:"Check for the libcollection-devel-3829 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a local denial-of-service attack that stops other
users from logging in. The bug existed in the pam_parse_in_data_v2()
function. (CVE-2010-4341: CVSS v2 Base Score: 2.1)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=660481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-01/msg00025.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libcollection-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcollection-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcollection1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdhash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdhash1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libini_config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libini_config1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/19");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"libcollection-devel-0.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libcollection1-0.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libdhash-devel-0.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libdhash1-0.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libini_config-devel-0.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libini_config1-0.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-sssd-config-1.1.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"sssd-1.1.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"sssd-ipa-provider-1.1.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"sssd-tools-1.1.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"sssd-32bit-1.1.0-2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}
