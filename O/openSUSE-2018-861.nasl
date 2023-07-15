#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-861.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111669);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-13796");

  script_name(english:"openSUSE Security Update : mailman (openSUSE-2018-861)");
  script_summary(english:"Check for the openSUSE-2018-861 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mailman fixes the following issues :

Security issue fixed :

  - CVE-2018-13796: Fix a content spoofing vulnerability
    with invalid list name messages inside the web UI
    (boo#1101288).

Bug fixes :

  - update to 2.1.29 :

  - Fixed the listinfo and admin overview pages that were
    broken 

  - update to 2.1.28 :

  - It is now possible to edit HTML and text templates via
    the web admin UI in a supported language other than the
    list's preferred_language.

  - The Japanese translation has been updated

  - The German translation has been updated

  - The Esperanto translation has been updated

  - The BLOCK_SPAMHAUS_LISTED_DBL_SUBSCRIBE feature added in
    2.1.27 was not working. This is fixed.

  - Escaping of HTML entities for the web UI is now done
    more selectively."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101288"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mailman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mailman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mailman-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/14");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"mailman-2.1.29-lp150.2.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mailman-debuginfo-2.1.29-lp150.2.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mailman-debugsource-2.1.29-lp150.2.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mailman-2.1.29-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mailman-debuginfo-2.1.29-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mailman-debugsource-2.1.29-2.11.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman / mailman-debuginfo / mailman-debugsource");
}
