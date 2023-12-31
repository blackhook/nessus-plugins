#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-804.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91888);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-5701", "CVE-2016-5703", "CVE-2016-5705", "CVE-2016-5706", "CVE-2016-5730", "CVE-2016-5731", "CVE-2016-5733", "CVE-2016-5739");

  script_name(english:"openSUSE Security Update : phpMyAdmin (openSUSE-2016-804)");
  script_summary(english:"Check for the openSUSE-2016-804 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin was updated to version 4.4.15.7 to fix eight security
issues.

These security issues were fixed :

  - CVE-2016-5701: BBCode injection vulnerability
    (boo#986154)

  - CVE-2016-5703: SQL injection attack (boo#986154)

  - CVE-2016-5705: Multiple XSS vulnerabilities (boo#986154)

  - CVE-2016-5706: DOS attack (boo#986154)

  - CVE-2016-5730: Multiple full path disclosure
    vulnerabilities (boo#986154)

  - CVE-2016-5731: XSS through FPD (boo#986154)

  - CVE-2016-5733: Multiple XSS vulnerabilities (boo#986154)

  - CVE-2016-5739: Referrer leak in transformations
    (boo#986154)

This non-security issues was fixed :

  - Fix issue Setup script doesn't use input type 'password'
    in all relevant locations"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986154"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"phpMyAdmin-4.4.15.7-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"phpMyAdmin-4.4.15.7-22.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
