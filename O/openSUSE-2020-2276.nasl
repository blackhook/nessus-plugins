#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2276.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145307);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/27");

  script_cve_id("CVE-2019-12625", "CVE-2019-12900", "CVE-2019-15961", "CVE-2019-1785", "CVE-2019-1786", "CVE-2019-1787", "CVE-2019-1788", "CVE-2019-1789", "CVE-2019-1798", "CVE-2020-3123", "CVE-2020-3327", "CVE-2020-3341", "CVE-2020-3350", "CVE-2020-3481");

  script_name(english:"openSUSE Security Update : clamav (openSUSE-2020-2276)");
  script_summary(english:"Check for the openSUSE-2020-2276 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for clamav fixes the following issues :

clamav was updated to the new major release 0.103.0.
(jsc#ECO-3010,bsc#1118459)

Note that libclamav was changed incompatible, if you have a 3rd party
application that uses libclamav, it needs to be rebuilt.

Update to 0.103.0

  - clamd can now reload the signature database without
    blocking scanning. This multi-threaded database reload
    improvement was made possible thanks to a community
    effort.

  - Non-blocking database reloads are now the default
    behavior. Some systems that are more constrained on RAM
    may need to disable non-blocking reloads as it will
    temporarily consume two times as much memory. We added a
    new clamd config option ConcurrentDatabaseReload, which
    may be set to no.

  - Fix clamav-milter.service (requires clamd.service to
    run)

Update to 0.102.4

  - CVE-2020-3350: Fix a vulnerability wherein a malicious
    user could replace a scan target's directory with a
    symlink to another path to trick clamscan, clamdscan, or
    clamonacc into removing or moving a different file (eg.
    a critical system file). The issue would affect users
    that use the --move or --remove options for clamscan,
    clamdscan, and clamonacc.

  - CVE-2020-3327: Fix a vulnerability in the ARJ archive
    parsing module in ClamAV 0.102.3 that could cause a
    Denial-of-Service (DoS) condition. Improper bounds
    checking results in an out-of-bounds read which could
    cause a crash. The previous fix for this CVE in 0.102.3
    was incomplete. This fix correctly resolves the issue.

  - CVE-2020-3481: Fix a vulnerability in the EGG archive
    module in ClamAV 0.102.0 - 0.102.3 could cause a
    Denial-of-Service (DoS) condition. Improper error
    handling may result in a crash due to a NULL pointer
    dereference. This vulnerability is mitigated for those
    using the official ClamAV signature databases because
    the file type signatures in daily.cvd will not enable
    the EGG archive parser in versions affected by the
    vulnerability.

Update to 0.102.3

  - CVE-2020-3327: Fix a vulnerability in the ARJ archive
    parsing module in ClamAV 0.102.2 that could cause a
    Denial-of-Service (DoS) condition. Improper bounds
    checking of an unsigned variable results in an
    out-of-bounds read which causes a crash.

  - CVE-2020-3341: Fix a vulnerability in the PDF parsing
    module in ClamAV 0.101 - 0.102.2 that could cause a
    Denial-of-Service (DoS) condition. Improper size
    checking of a buffer used to initialize AES decryption
    routines results in an out-of-bounds read which may
    cause a crash.

  - Fix 'Attempt to allocate 0 bytes' error when parsing
    some PDF documents.

  - Fix a couple of minor memory leaks.

  - Updated libclamunrar to UnRAR 5.9.2.

Update to 0.102.2 :

  - CVE-2020-3123: A denial-of-service (DoS) condition may
    occur when using the optional credit card
    data-loss-prevention (DLP) feature. Improper bounds
    checking of an unsigned variable resulted in an
    out-of-bounds read, which causes a crash.

  - Significantly improved the scan speed of PDF files on
    Windows.

  - Re-applied a fix to alleviate file access issues when
    scanning RAR files in downstream projects that use
    libclamav where the scanning engine is operating in a
    low-privilege process. This bug was originally fixed in
    0.101.2 and the fix was mistakenly omitted from 0.102.0.

  - Fixed an issue where freshclam failed to update if the
    database version downloaded is one version older than
    advertised. This situation may occur after a new
    database version is published. The issue affected users
    downloading the whole CVD database file.

  - Changed the default freshclam ReceiveTimeout setting to
    0 (infinite). The ReceiveTimeout had caused needless
    database update failures for users with slower internet
    connections.

  - Correctly display the number of kilobytes (KiB) in
    progress bar and reduced the size of the progress bar to
    accommodate 80-character width terminals.

  - Fixed an issue where running freshclam manually causes a
    daemonized freshclam process to fail when it updates
    because the manual instance deletes the temporary
    download directory. The freshclam temporary files will
    now download to a unique directory created at the time
    of an update instead of using a hardcoded directory
    created/destroyed at the program start/exit.

  - Fix for freshclam's OnOutdatedExecute config option.

  - Fixes a memory leak in the error condition handling for
    the email parser.

  - Improved bound checking and error handling in ARJ
    archive parser.

  - Improved error handling in PDF parser.

  - Fix for memory leak in byte-compare signature handler.

  - The freshclam.service should not be started before the
    network is online (it checks for updates immediately
    upon service start)

Update to 0.102.1 :

  - CVE-2019-15961, bsc#1157763: A Denial-of-Service (DoS)
    vulnerability may occur when scanning a specially
    crafted email file as a result of excessively long scan
    times. The issue is resolved by implementing several
    maximums in parsing MIME messages and by optimizing use
    of memory allocation.

  - Build system fixes to build clamav-milter, to correctly
    link with libxml2 when detected, and to correctly detect
    fanotify for on-access scanning feature support.

  - Signature load time is significantly reduced by changing
    to a more efficient algorithm for loading signature
    patterns and allocating the AC trie. Patch courtesy of
    Alberto Wu.

  - Introduced a new configure option to statically link
    libjson-c with libclamav. Static linking with libjson is
    highly recommended to prevent crashes in applications
    that use libclamav alongside another JSON parsing
    library.

  - Null-dereference fix in email parser when using the

    --gen-json metadata option.

  - Fixes for Authenticode parsing and certificate signature
    (.crb database) bugs.

Update to 0.102.0 :

  - The On-Access Scanning feature has been migrated out of
    clamd and into a brand new utility named clamonacc. This
    utility is similar to clamdscan and clamav-milter in
    that it acts as a client to clamd. This separation from
    clamd means that clamd no longer needs to run with root
    privileges while scanning potentially malicious files.
    Instead, clamd may drop privileges to run under an
    account that does not have super-user. In addition to
    improving the security posture of running clamd with
    On-Access enabled, this update fixed a few outstanding
    defects :

  - On-Access scanning for created and moved files
    (Extra-Scanning) is fixed.

  - VirusEvent for On-Access scans is fixed.

  - With clamonacc, it is now possible to copy, move, or
    remove a file if the scan triggered an alert, just like
    with clamdscan.

  - The freshclam database update utility has undergone a
    significant update. This includes :

  - Added support for HTTPS.

  - Support for database mirrors hosted on ports other than
    80.

  - Removal of the mirror management feature (mirrors.dat).

  - An all new libfreshclam library API.

  - created new subpackage libfreshclam2

Update to 0.101.4 :

  - CVE-2019-12900: An out of bounds write in the NSIS bzip2
    (bsc#1149458)

  - CVE-2019-12625: Introduce a configurable time limit to
    mitigate zip bomb vulnerability completely. Default is 2
    minutes, configurable useing the clamscan --max-scantime
    and for clamd using the MaxScanTime config option
    (bsc#1144504)

Update to version 0.101.3 :

  - bsc#1144504: ZIP bomb causes extreme CPU spikes

Update to version 0.101.2 (bsc#1130721)

  - CVE-2019-1787: An out-of-bounds heap read condition may
    occur when scanning PDF documents. The defect is a
    failure to correctly keep track of the number of bytes
    remaining in a buffer when indexing file data.

  - CVE-2019-1789: An out-of-bounds heap read condition may
    occur when scanning PE files (i.e. Windows EXE and DLL
    files) that have been packed using Aspack as a result of
    inadequate bound-checking.

  - CVE-2019-1788: An out-of-bounds heap write condition may
    occur when scanning OLE2 files such as Microsoft Office
    97-2003 documents. The invalid write happens when an
    invalid pointer is mistakenly used to initialize a 32bit
    integer to zero. This is likely to crash the
    application.

  - CVE-2019-1786: An out-of-bounds heap read condition may
    occur when scanning malformed PDF documents as a result
    of improper bounds-checking.

  - CVE-2019-1785: A path-traversal write condition may
    occur as a result of improper input validation when
    scanning RAR archives.

  - CVE-2019-1798: A use-after-free condition may occur as a
    result of improper error handling when scanning nested
    RAR archives.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157763"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected clamav packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclamav9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclamav9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreshclam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreshclam2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"clamav-0.103.0-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"clamav-debuginfo-0.103.0-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"clamav-debugsource-0.103.0-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"clamav-devel-0.103.0-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libclamav9-0.103.0-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libclamav9-debuginfo-0.103.0-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfreshclam2-0.103.0-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfreshclam2-debuginfo-0.103.0-lp152.6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-debuginfo / clamav-debugsource / clamav-devel / etc");
}
