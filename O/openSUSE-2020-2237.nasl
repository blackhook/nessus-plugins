#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2237.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(144316);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/18");

  script_cve_id("CVE-2020-26137");

  script_name(english:"openSUSE Security Update : python-urllib3 (openSUSE-2020-2237)");
  script_summary(english:"Check for the openSUSE-2020-2237 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for python-urllib3 fixes the following issues :

  - CVE-2020-26137: Fixed a CRLF injection via HTTP request
    method (bsc#1177120).&#9; 

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177120"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected python-urllib3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-urllib3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-urllib3-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"python2-urllib3-1.24-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python2-urllib3-test-1.24-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-urllib3-1.24-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-urllib3-test-1.24-lp152.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-urllib3 / python3-urllib3 / python2-urllib3-test / etc");
}
