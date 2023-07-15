#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1095.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139020);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/30");

  script_cve_id("CVE-2020-14039", "CVE-2020-15586");

  script_name(english:"openSUSE Security Update : go1.13 (openSUSE-2020-1095)");
  script_summary(english:"Check for the openSUSE-2020-1095 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for go1.13 fixes the following issues :

  - go1.13.14 (released 2020/07/16) includes fixes to the
    compiler, vet, and the database/sql, net/http, and
    reflect packages Refs bsc#1149259 go1.13 release
    tracking

  - go#39925 net/http: panic on misformed If-None-Match
    Header with http.ServeContent

  - go#39848 cmd/compile: internal compile error when using
    sync.Pool: mismatched zero/store sizes

  - go#39823 cmd/go: TestBuildIDContainsArchModeEnv/386
    fails on linux/386 in Go 1.14 and 1.13, not 1.15

  - go#39697 reflect: panic from malloc after MakeFunc
    function returns value that is also stored globally

  - go#39561 cmd/compile/internal/ssa:
    TestNexting/dlv-dbg-hist failing on linux-386-longtest
    builder because it tries to use an older version of dlv
    which only supports linux/amd64

  - go#39538 net: TestDialParallel is flaky on
    windows-amd64-longtest

  - go#39287 cmd/vet: update for new number formats

  - go#40211 net/http: Expect 100-continue panics in
    httputil.ReverseProxy bsc#1174153 CVE-2020-15586

  - go#40209 crypto/x509: Certificate.Verify method
    seemingly ignoring EKU requirements on Windows
    bsc#1174191 CVE-2020-14039 (Windows only)

  - go#38932 runtime: preemption in startTemplateThread may
    cause infinite hang

  - go#36689 go/types, math/big: data race in go/types due
    to math/big.Rat accessors unsafe for concurrent use

  - Add patch to ensure /etc/hosts is used if
    /etc/nsswitch.conf is not present bsc#1172868
    gh#golang/go#35305

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174191"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected go1.13 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14039");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.13-race");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");
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

if ( rpm_check(release:"SUSE15.2", reference:"go1.13-1.13.14-lp152.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"go1.13-race-1.13.14-lp152.2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "go1.13 / go1.13-race");
}
