#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1407.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140570);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/04");

  script_cve_id("CVE-2020-14039", "CVE-2020-15586", "CVE-2020-16845");
  script_xref(name:"IAVB", value:"2020-B-0060-S");

  script_name(english:"openSUSE Security Update : go1.14 (openSUSE-2020-1407)");
  script_summary(english:"Check for the openSUSE-2020-1407 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for go1.14 fixes the following issues :

  - go1.14 was updated to version 1.14.7 

  - CVE-2020-16845: dUvarint and ReadVarint can read an
    unlimited number of bytes from invalid inputs
    (bsc#1174977).&#9; 

  - go1.14.6 (released 2020-07-16) includes fixes to the go
    command, the compiler, the linker, vet, and the
    database/sql, encoding/json, net/http, reflect, and
    testing packages. Refs bsc#1164903 go1.14 release
    tracking Refs bsc#1174153 bsc#1174191

  - go#39991 runtime: missing deferreturn on linux/ppc64le

  - go#39920 net/http: panic on misformed If-None-Match
    Header with http.ServeContent

  - go#39849 cmd/compile: internal compile error when using
    sync.Pool: mismatched zero/store sizes

  - go#39824 cmd/go: TestBuildIDContainsArchModeEnv/386
    fails on linux/386 in Go 1.14 and 1.13, not 1.15

  - go#39698 reflect: panic from malloc after MakeFunc
    function returns value that is also stored globally

  - go#39636 reflect: DeepEqual can return true for values
    that are not equal

  - go#39585 encoding/json: incorrect object key
    unmarshaling when using custom TextUnmarshaler as Key
    with string va lues

  - go#39562 cmd/compile/internal/ssa:
    TestNexting/dlv-dbg-hist failing on linux-386-longtest
    builder because it trie s to use an older version of dlv
    which only supports linux/amd64

  - go#39308 testing: streaming output loses parallel
    subtest associations

  - go#39288 cmd/vet: update for new number formats

  - go#39101 database/sql: context cancellation allows
    statements to execute after rollback

  - go#38030 doc: BuildNameToCertificate deprecated in go
    1.14 not mentioned in the release notes

  - go#40212 net/http: Expect 100-continue panics in
    httputil.ReverseProxy bsc#1174153 CVE-2020-15586

  - go#40210 crypto/x509: Certificate.Verify method
    seemingly ignoring EKU requirements on Windows
    bsc#1174191 CVE-2020-14039 (Windows only)

  - Add patch to ensure /etc/hosts is used if
    /etc/nsswitch.conf is not present bsc#1172868
    gh#golang/go#35305

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174977");
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected go1.14 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14039");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.14-race");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/14");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"go1.14-1.14.7-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"go1.14-race-1.14.7-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "go1.14 / go1.14-race");
}
