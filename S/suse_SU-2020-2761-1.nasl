#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2761-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143750);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-24553");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : go1.14 (SUSE-SU-2020:2761-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for go1.14 fixes the following issues :

go1.14.9 (released 2020-09-09) includes fixes to the compiler, linker,
runtime, documentation, and the net/http and testing packages. Refs
bsc#1164903 go1.14 release tracking

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

go1.14.8 (released 2020-09-01) includes security fixes to the
net/http/cgi and net/http/fcgi packages. CVE-2020-24553 Refs
bsc#1164903 go1.14 release tracking

  - bsc#1176031 CVE-2020-24553

  - go#41164 net/http/cgi,net/http/fcgi: Cross-Site
    Scripting (XSS) when Content-Type is not specified

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1164903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-24553/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202761-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e629fac"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP2-2020-2761=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-2761=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.14-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
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
if (rpm_check(release:"SLES15", sp:"1", reference:"go1.14-1.14.9-1.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"go1.14-doc-1.14.9-1.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"go1.14-1.14.9-1.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"go1.14-doc-1.14.9-1.18.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"go1.14-1.14.9-1.18.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"go1.14-doc-1.14.9-1.18.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"go1.14-1.14.9-1.18.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"go1.14-doc-1.14.9-1.18.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "go1.14");
}
