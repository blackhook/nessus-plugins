#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2776-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143651);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-24553");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : go1.15 (SUSE-SU-2020:2776-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"go1.15 (released 2020-08-11) Go 1.15 is a major release of Go.

go1.15.x minor releases will be provided through August 2021.

https://github.com/golang/go/wiki/Go-Release-Cycle

Most changes are in the implementation of the toolchain, runtime, and
libraries. As always, the release maintains the Go 1 promise of
compatibility. We expect almost all Go programs to continue to compile
and run as before.

See release notes https://golang.org/doc/go1.15. Excerpts relevant to
OBS environment and for SUSE/openSUSE follow :

Module support in the go command is ready for production use, and we
encourage all users to migrate to Go modules for dependency
management.

Module cache: The location of the module cache may now be set with the
GOMODCACHE environment variable. The default value of GOMODCACHE is
GOPATH[0]/pkg/mod, the location of the module cache before this
change.

Compiler flag parsing: Various flag parsing issues in go test and go
vet have been fixed. Notably, flags specified in GOFLAGS are handled
more consistently, and the -outputdir flag now interprets relative
paths relative to the working directory of the go command (rather than
the working directory of each individual test).

The GOPROXY environment variable now supports skipping proxies that
return errors. Proxy URLs may now be separated with either commas (,)
or pipe characters (|). If a proxy URL is followed by a comma, the go
command will only try the next proxy in the list after a 404 or 410
HTTP response. If a proxy URL is followed by a pipe character, the go
command will try the next proxy in the list after any error. Note that
the default value of GOPROXY remains https://proxy.golang.org,direct,
which does not fall back to direct in case of errors.

On a Unix system, if the kill command or kill system call is used to
send a SIGSEGV, SIGBUS, or SIGFPE signal to a Go program, and if the
signal is not being handled via os/signal.Notify, the Go program will
now reliably crash with a stack trace. In earlier releases the
behavior was unpredictable.

Allocation of small objects now performs much better at high core
counts, and has lower worst-case latency.

Go 1.15 reduces typical binary sizes by around 5% compared to Go 1.14
by eliminating certain types of GC metadata and more aggressively
eliminating unused type metadata.

The toolchain now mitigates Intel CPU erratum SKX102 on GOARCH=amd64
by aligning functions to 32 byte boundaries and padding jump
instructions. While this padding increases binary sizes, this is more
than made up for by the binary size improvements mentioned above.

Go 1.15 adds a -spectre flag to both the compiler and the assembler,
to allow enabling Spectre mitigations. These should almost never be
needed and are provided mainly as a 'defense in depth' mechanism. See
the Spectre Go wiki page for details.

The compiler now rejects //go: compiler directives that have no
meaning for the declaration they are applied to with a 'misplaced
compiler directive' error. Such misapplied directives were broken
before, but were silently ignored by the compiler.

Substantial improvements to the Go linker, which reduce linker
resource usage (both time and memory) and improve code
robustness/maintainability. Linking is 20% faster and requires 30%
less memory on average. These changes are part of a multi-release
project to modernize the Go linker, meaning that there will be
additional linker improvements expected in future releases.

The linker now defaults to internal linking mode for

-buildmode=pie on linux/amd64 and linux/arm64, so these configurations
no longer require a C linker.

There has been progress in improving the stability and performance of
the 64-bit RISC-V port on Linux (GOOS=linux, GOARCH=riscv64). It also
now supports asynchronous preemption.

crypto/x509: The deprecated, legacy behavior of treating the
CommonName field on X.509 certificates as a host name when no Subject
Alternative Names are present is now disabled by default. It can be
temporarily re-enabled by adding the value x509ignoreCN=0 to the
GODEBUG environment variable. Note that if the CommonName is an
invalid host name, it's always ignored, regardless of GODEBUG
settings. Invalid names include those with any characters other than
letters, digits, hyphens and underscores, and those with empty labels
or trailing dots.

crypto/x509: go1.15 applications with an AWS DB instance that was
created or updated to the rds-ca-2019 certificate prior to July 28,
2020, you must update the certificate again. If you created your DB
instance or updated its certificate after July 28, 2020, no action is
required. For more information, see go#39568

This update ships go1.15.2 (released 2020-09-09) includes fixes to the
compiler, runtime, documentation, the go command, and the net/mail,
os, sync, and testing packages.

go#41193 net/http/fcgi: race detected during execution of
TestResponseWriterSniffsContentType test

go#41178 doc: include fix for #34437 in Go 1.14 release notes

go#41034 testing: Cleanup races with Logf and Errorf

go#41011 sync: sync.Map keys will never be garbage collected

go#40934 runtime: checkptr incorrectly -race flagging when using &^
arithmetic

go#40900 internal/poll: CopyFileRange returns EPERM on CircleCI Docker
Host running 4.10.0-40-generic

go#40868 cmd/compile: R12 can be clobbered for write barrier call on
PPC64

go#40849 testing: '=== PAUSE' lines do not change the test name for
the next log line

go#40845 runtime: Panic if newstack at runtime.acquireLockRank

go#40805 cmd/test2json: tests that panic are marked as passing

go#40804 net/mail: change in behavior of ParseAddressList('') in 1.15

go#40802 cmd/go: in 1.15: change in 'go test' argument parsing

go#40798 cmd/compile: inline marker targets not reachable after
assembly on arm

go#40772 cmd/compile: compiler crashes in ssa: isNonNegative bad type

go#40767 cmd/compile: inline marker targets not reachable after
assembly on ppc64x

go#40739 internal/poll: CopyFileRange returns ENOTSUP on Linux 3.10.0
kernel on NFS mount

go#40412 runtime: Windows service lifecycle events behave incorrectly
when called within a golang environment

go1.15.1 (released 2020-09-01) includes security fixes to the
net/http/cgi and net/http/fcgi packages.

bsc#1176031 CVE-2020-24553: go net/http/cgi,net/http/fcgi: Cross-Site
Scripting (XSS) when Content-Type is not specified

go#41165 net/http/cgi,net/http/fcgi: Cross-Site Scripting (XSS) when
Content-Type is not specified

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1170826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1175132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/golang/go/wiki/Go-Release-Cycle"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://golang.org/doc/go1.15."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://proxy.golang.org,direct,"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-24553/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202776-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6691df4"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP2-2020-2776=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-2776=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.15-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"go1.15-1.15.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"go1.15-doc-1.15.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"go1.15-1.15.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"go1.15-doc-1.15.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"go1.15-1.15.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"go1.15-doc-1.15.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"go1.15-1.15.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"go1.15-doc-1.15.2-1.3.1")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "go1.15");
}
