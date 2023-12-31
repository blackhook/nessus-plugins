#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update logrotate-4580.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75942);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-1098", "CVE-2011-1154", "CVE-2011-1155");

  script_name(english:"openSUSE Security Update : logrotate (openSUSE-SU-2011:0536-1)");
  script_summary(english:"Check for the logrotate-4580 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for logrotate provides the following fixes :

dbg114-logrotate-4580 logrotate-4580 new_updateinfo The shred_file
function in logrotate might allow context-dependent attackers to
execute arbitrary commands via shell metacharacters in a log filename,
as demonstrated by a filename that is automatically constructed on the
basis of a hostname or virtual machine name (CVE-2011-1154)
(bnc#679661)

dbg114-logrotate-4580 logrotate-4580 new_updateinfo Race condition in
the createOutputFile function in logrotate allows local users to read
log data by opening a file before the intended permissions are in
place (CVE-2011-1098) (bnc#677336)

dbg114-logrotate-4580 logrotate-4580 new_updateinfo The writeState
function in logrotate might allow context-dependent attackers to cause
a denial of service (rotation outage) via a (1) n (newline) or (2)
(backslash) character in a log filename, as demonstrated by a filename
that is automatically constructed on the basis of a hostname or
virtual machine name (CVE-2011-1155) (bnc#679662)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=677336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-05/msg00055.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected logrotate packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:logrotate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:logrotate-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:logrotate-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/18");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"logrotate-3.7.9-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"logrotate-debuginfo-3.7.9-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"logrotate-debugsource-3.7.9-6.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "logrotate");
}
