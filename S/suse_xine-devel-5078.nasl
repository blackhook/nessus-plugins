#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xine-devel-5078.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31459);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-0486");

  script_name(english:"openSUSE 10 Security Update : xine-devel (xine-devel-5078)");
  script_summary(english:"Check for the xine-devel-5078 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of xine fixes a possible buffer overflow that can be
triggered via FLAC tags to execute arbitrary code (CVE-2008-0486) and
a possible buffer overflow in the matroska demuxer."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xine-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-lib-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-ui-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"xine-devel-1.1.1-24.29") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xine-extra-1.1.1-24.29") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xine-lib-1.1.1-24.29") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xine-ui-0.99.4-32.25") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"xine-lib-32bit-1.1.1-24.29") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xine-devel-1.1.2-40.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xine-extra-1.1.2-40.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xine-lib-1.1.2-40.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xine-ui-0.99.4-84.4") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"xine-lib-32bit-1.1.2-40.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"xine-ui-32bit-0.99.4-84.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xine-lib");
}
