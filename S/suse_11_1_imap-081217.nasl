#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update imap-368.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40232);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-5006", "CVE-2008-5514");

  script_name(english:"openSUSE Security Update : imap (imap-368)");
  script_summary(english:"Check for the imap-368 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Insufficient buffer length checks in the imap client library may crash
applications that use the library to print formatted email addresses.
The imap daemon itself is not affected but certain versions of e.g.
the php imap module are (CVE-2008-5514).

The client library could also crash when a rogue server unexpectedly
closes the connection (CVE-2008-5006)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=458579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=459037"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected imap packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imap-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"imap-devel-2006c1_suse-127.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"imap-lib-2006c1_suse-127.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imap-devel / imap-lib");
}
