#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-34.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106063);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-9512", "CVE-2017-16548", "CVE-2017-17433", "CVE-2017-17434");

  script_name(english:"openSUSE Security Update : rsync (openSUSE-2018-34)");
  script_summary(english:"Check for the openSUSE-2018-34 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for rsync fixes the several issues.

These security issues were fixed :

  - CVE-2017-17434: The daemon in rsync did not check for
    fnamecmp filenames in the daemon_filter_list data
    structure (in the recv_files function in receiver.c) and
    also did not apply the sanitize_paths protection
    mechanism to pathnames found in 'xname follows' strings
    (in the read_ndx_and_attrs function in rsync.c), which
    allowed remote attackers to bypass intended access
    restrictions' (bsc#1071460).

  - CVE-2017-17433: The recv_files function in receiver.c in
    the daemon in rsync, proceeded with certain file
    metadata updates before checking for a filename in the
    daemon_filter_list data structure, which allowed remote
    attackers to bypass intended access restrictions
    (bsc#1071459).

  - CVE-2017-16548: The receive_xattr function in xattrs.c
    in rsync did not check for a trailing '\\0' character in
    an xattr name, which allowed remote attackers to cause a
    denial of service (heap-based buffer over-read and
    application crash) or possibly have unspecified other
    impact by sending crafted data to the daemon
    (bsc#1066644).

  - CVE-2014-9512: Prevent attackers to write to arbitrary
    files via a symlink attack on a file in the
    synchronization path (bsc#915410).

These non-security issues were fixed :

  - Stop file upload after errors like a full disk
    (boo#1062063)

  - Ensure -X flag works even when setting owner/group
    (boo#1028842)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999847"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsync packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsync-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsync-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"rsync-3.1.0-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rsync-debuginfo-3.1.0-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rsync-debugsource-3.1.0-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rsync-3.1.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rsync-debuginfo-3.1.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rsync-debugsource-3.1.0-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsync / rsync-debuginfo / rsync-debugsource");
}
