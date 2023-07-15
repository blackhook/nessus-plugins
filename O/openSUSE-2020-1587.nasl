#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1587.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141162);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/07");

  script_cve_id("CVE-2020-24553");

  script_name(english:"openSUSE Security Update : go1.14 (openSUSE-2020-1587)");
  script_summary(english:"Check for the openSUSE-2020-1587 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for go1.14 fixes the following issues :

  - go1.14.9 (released 2020-09-09) includes fixes to the
    compiler, linker, runtime, documentation, and the
    net/http and testing packages. Refs bsc#1164903 go1.14
    release tracking

  - go#41192 net/http/fcgi: race detected during execution
    of TestResponseWriterSniffsContentType test

  - go#41016 net/http: Transport.CancelRequest no longer
    cancels in-flight request

  - go#40973 net/http: RoundTrip unexpectedly changes
    Request

  - go#40968 runtime: checkptr incorrectly -race flagging
    when using &^ arithmetic

  - go#40938 cmd/compile: R12 can be clobbered for write
    barrier call on PPC64

  - go#40848 testing: '=== PAUSE' lines do not change the
    test name for the next log line

  - go#40797 cmd/compile: inline marker targets not
    reachable after assembly on arm

  - go#40766 cmd/compile: inline marker targets not
    reachable after assembly on ppc64x

  - go#40501 cmd/compile: for range loop reading past slice
    end

  - go#40411 runtime: Windows service lifecycle events
    behave incorrectly when called within a golang
    environment

  - go#40398 runtime: fatal error: checkdead: runnable g

  - go#40192 runtime: pageAlloc.searchAddr may point to
    unmapped memory in discontiguous heaps, violating its
    invariant

  - go#39955 cmd/link: incorrect GC bitmap when global's
    type is in another shared object

  - go#39690 cmd/compile: s390x floating point <-> integer
    conversions clobbering the condition code

  - go#39279 net/http: Re-connect with upgraded HTTP2
    connection fails to send Request.body

  - go#38904 doc: include fix for #34437 in Go 1.14 release
    notes

  - go1.14.8 (released 2020-09-01) includes security fixes
    to the net/http/cgi and net/http/fcgi packages.
    CVE-2020-24553 Refs bsc#1164903 go1.14 release tracking

  - bsc#1176031 CVE-2020-24553

  - go#41164 net/http/cgi,net/http/fcgi: Cross-Site
    Scripting (XSS) when Content-Type is not specified This
    update was imported from the SUSE:SLE-15:Update update
    project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176031"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected go1.14 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.14-race");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");
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

if ( rpm_check(release:"SUSE15.2", reference:"go1.14-1.14.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"go1.14-race-1.14.9-lp152.2.6.1") ) flag++;

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
