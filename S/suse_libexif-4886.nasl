#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libexif-4886.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29958);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-6351", "CVE-2007-6352");

  script_name(english:"openSUSE 10 Security Update : libexif (libexif-4886)");
  script_summary(english:"Check for the libexif-4886 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two bugs in libexif were identified by a Google Security Audit done by
Meder Kydyraliev.

CVE-2007-6351: Loading EXIF data could be used to cause a infinite
recursion and crash CVE-2007-6352: Integer overflows in the thumbnail
handler could be used to overflow buffers and potentially execute code
or crash a program using libexif."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libexif packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"libexif-0.6.13-20.9") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"libexif-32bit-0.6.13-20.9") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libexif-0.6.14-22") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"libexif-32bit-0.6.14-22") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libexif-0.6.16-23.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libexif-devel-0.6.16-23.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libexif-32bit-0.6.16-23.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libexif");
}
