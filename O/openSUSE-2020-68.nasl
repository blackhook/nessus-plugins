#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-68.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133130);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-20009", "CVE-2019-20010", "CVE-2019-20011", "CVE-2019-20012", "CVE-2019-20013", "CVE-2019-20014", "CVE-2019-20015", "CVE-2019-9770", "CVE-2019-9771", "CVE-2019-9772", "CVE-2019-9773", "CVE-2019-9774", "CVE-2019-9775", "CVE-2019-9776", "CVE-2019-9777", "CVE-2019-9778", "CVE-2019-9779");

  script_name(english:"openSUSE Security Update : libredwg (openSUSE-2020-68)");
  script_summary(english:"Check for the openSUSE-2020-68 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libredwg fixes the following issues :

libredwg was updated to release 0.9.3 :

  - Added the -x,--extnames option to dwglayers for r13-r14
    DWGs.

  - Fixed some leaks: SORTENTSTABLE,
    PROXY_ENTITY.ownerhandle for r13.

  - Add DICTIONARY.itemhandles[] for r13 and r14.

  - Fixed some dwglayers NULL pointer derefs, and flush its
    output for each layer.

  - Added several overflow checks from fuzzing
    [CVE-2019-20010, boo#1159825], [CVE-2019-20011,
    boo#1159826], [CVE-2019-20012, boo#1159827],
    [CVE-2019-20013, boo#1159828], [CVE-2019-20014,
    boo#1159831], [CVE-2019-20015, boo#1159832]

  - Disallow illegal SPLINE scenarios [CVE-2019-20009,
    boo#1159824]

Update to release 0.9.1 :

  - Fixed more NULL pointer dereferences, overflows, hangs
    and memory leaks for fuzzed (i.e. illegal) DWGs.

Update to release 0.9 [boo#1154080] :

  - Added the DXF importer, using the new dynapi and the
    r2000 encoder. Only for r2000 DXFs.

  - Added utf8text conversion functions to the dynapi.

  - Added 3DSOLID encoder.

  - Added APIs to find handles for names, searching in
    tables and dicts.

  - API breaking changes - see NEWS file in package.

  - Fixed NULL pointer dereferences, and memory leaks
    (except DXF importer) [boo#1129868, CVE-2019-9779]
    [boo#1129869, CVE-2019-9778] [boo#1129870,
    CVE-2019-9777] [boo#1129873, CVE-2019-9776]
    [boo#1129874, CVE-2019-9773] [boo#1129875,
    CVE-2019-9772] [boo#1129876, CVE-2019-9771]
    [boo#1129878, CVE-2019-9775] [boo#1129879,
    CVE-2019-9774] [boo#1129881, CVE-2019-9770]

Update to 0.8 :

  - add a new dynamic API, read and write all header and
    object fields by name

  - API breaking changes

  - Fix many errors in DXF output

  - Fix JSON output

  - Many more bug fixes to handle specific object types"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159832"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libredwg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20014");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libredwg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libredwg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libredwg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libredwg-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libredwg-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libredwg0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libredwg0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libredwg-debuginfo-0.9.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libredwg-debugsource-0.9.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libredwg-devel-0.9.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libredwg-tools-0.9.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libredwg-tools-debuginfo-0.9.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libredwg0-0.9.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libredwg0-debuginfo-0.9.3-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libredwg-debuginfo / libredwg-debugsource / libredwg-devel / etc");
}
