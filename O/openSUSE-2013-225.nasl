#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-225.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74932);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-5526", "CVE-2012-6329", "CVE-2013-1667");
  script_bugtraq_id(56562, 56950, 58311);

  script_name(english:"openSUSE Security Update : perl (openSUSE-SU-2013:0497-1)");
  script_summary(english:"Check for the openSUSE-2013-225 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Perl was updated to fix 3 security issues :

  - fix rehash denial of service (compute time) [bnc#804415]
    [CVE-2013-1667]

  - improve CGI crlf escaping [bnc#789994] [CVE-2012-5526]

  - sanitize input in Maketext.pm to avoid code injection
    [bnc#797060] [CVE-2012-6329]

In openSUSE 12.1 also the following non-security bug was fixed :

  - fix IPC::Open3 bug when '-' is used [bnc#755278]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-03/msg00068.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Foswiki 1.1.5 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki MAKETEXT Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"perl-5.14.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-base-5.14.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-base-debuginfo-5.14.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-debuginfo-5.14.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-debugsource-5.14.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"perl-32bit-5.14.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"perl-base-32bit-5.14.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"perl-base-debuginfo-32bit-5.14.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"perl-debuginfo-32bit-5.14.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-5.16.0-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-base-5.16.0-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-base-debuginfo-5.16.0-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-debuginfo-5.16.0-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-debugsource-5.16.0-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"perl-32bit-5.16.0-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"perl-base-32bit-5.16.0-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"perl-base-debuginfo-32bit-5.16.0-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"perl-debuginfo-32bit-5.16.0-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-5.16.2-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-base-5.16.2-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-base-debuginfo-5.16.2-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-debuginfo-5.16.2-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-debugsource-5.16.2-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"perl-32bit-5.16.2-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"perl-base-32bit-5.16.2-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"perl-base-debuginfo-32bit-5.16.2-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"perl-debuginfo-32bit-5.16.2-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-32bit / perl / perl-base-32bit / perl-base / etc");
}
