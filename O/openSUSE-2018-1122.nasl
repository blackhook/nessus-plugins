#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1122.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117979);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-15908", "CVE-2018-15909", "CVE-2018-15910", "CVE-2018-15911", "CVE-2018-16509", "CVE-2018-16510", "CVE-2018-16511", "CVE-2018-16513", "CVE-2018-16539", "CVE-2018-16540", "CVE-2018-16541", "CVE-2018-16542", "CVE-2018-16543", "CVE-2018-16585", "CVE-2018-16802", "CVE-2018-17183");

  script_name(english:"openSUSE Security Update : ghostscript (openSUSE-2018-1122)");
  script_summary(english:"Check for the openSUSE-2018-1122 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ghostscript to version 9.25 fixes the following 
issues :

These security issues were fixed :

  - CVE-2018-17183: Remote attackers were be able to supply
    crafted PostScript to potentially overwrite or replace
    error handlers to inject code (bsc#1109105)

  - CVE-2018-15909: Prevent type confusion using the .shfill
    operator that could have been used by attackers able to
    supply crafted PostScript files to crash the interpreter
    or potentially execute code (bsc#1106172).

  - CVE-2018-15908: Prevent attackers that are able to
    supply malicious PostScript files to bypass .tempfile
    restrictions and write files (bsc#1106171).

  - CVE-2018-15910: Prevent a type confusion in the
    LockDistillerParams parameter that could have been used
    to crash the interpreter or execute code (bsc#1106173).

  - CVE-2018-15911: Prevent use uninitialized memory access
    in the aesdecode operator that could have been used to
    crash the interpreter or potentially execute code
    (bsc#1106195).

  - CVE-2018-16513: Prevent a type confusion in the setcolor
    function that could have been used to crash the
    interpreter or possibly have unspecified other impact
    (bsc#1107412).

  - CVE-2018-16509: Incorrect 'restoration of privilege'
    checking during handling of /invalidaccess exceptions
    could be have been used by attackers able to supply
    crafted PostScript to execute code using the 'pipe'
    instruction (bsc#1107410).

  - CVE-2018-16510: Incorrect exec stack handling in the
    'CS' and 'SC' PDF primitives could have been used by
    remote attackers able to supply crafted PDFs to crash
    the interpreter or possibly have unspecified other
    impact (bsc#1107411).

  - CVE-2018-16542: Prevent attackers able to supply crafted
    PostScript files from using insufficient interpreter
    stack-size checking during error handling to crash the
    interpreter (bsc#1107413).

  - CVE-2018-16541: Prevent attackers able to supply crafted
    PostScript files from using incorrect free logic in
    pagedevice replacement to crash the interpreter
    (bsc#1107421).

  - CVE-2018-16540: Prevent use-after-free in copydevice
    handling that could have been used to crash the
    interpreter or possibly have unspecified other impact
    (bsc#1107420).

  - CVE-2018-16539: Prevent attackers able to supply crafted
    PostScript files from using incorrect access checking in
    temp file handling to disclose contents of files on the
    system otherwise not readable (bsc#1107422).

  - CVE-2018-16543: gssetresolution and gsgetresolution
    allowed attackers to have an unspecified impact
    (bsc#1107423).

  - CVE-2018-16511: A type confusion in 'ztype' could have
    been used by remote attackers able to supply crafted
    PostScript to crash the interpreter or possibly have
    unspecified other impact (bsc#1107426).

  - CVE-2018-16585: The .setdistillerkeys PostScript command
    was accepted even though it is not intended for use
    during document processing (e.g., after the startup
    phase). This lead to memory corruption, allowing remote
    attackers able to supply crafted PostScript to crash the
    interpreter or possibly have unspecified other impact
    (bsc#1107581).

  - CVE-2018-16802: Incorrect 'restoration of privilege'
    checking when running out of stack during exception
    handling could have been used by attackers able to
    supply crafted PostScript to execute code using the
    'pipe' instruction. This is due to an incomplete fix for
    CVE-2018-16509 (bsc#1108027).

These non-security issues were fixed :

  - Fixes problems with argument handling, some unintended
    results of the security fixes to the SAFER file access
    restrictions (specifically accessing ICC profile files).

  - Avoid that ps2epsi fails with 'Error: /undefined in
    --setpagedevice--'

For additional changes please check
http://www.ghostscript.com/doc/9.25/News.htm and the changes file of
the package. This update was imported from the SUSE:SLE-12:Update
update project."
  );
  # http://www.ghostscript.com/doc/9.25/News.htm
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ghostscript.com/doc/9.25/News.htm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109105"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ghostscript Failed Restore Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-9.25-14.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-debuginfo-9.25-14.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-debugsource-9.25-14.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-devel-9.25-14.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-9.25-14.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-debuginfo-9.25-14.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-debugsource-9.25-14.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-devel-9.25-14.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-x11-9.25-14.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-x11-debuginfo-9.25-14.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript-mini / ghostscript-mini-debuginfo / etc");
}
