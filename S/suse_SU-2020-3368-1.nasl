#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3368-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143660);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/02");

  script_cve_id("CVE-2020-28362", "CVE-2020-28366", "CVE-2020-28367");
  script_xref(name:"IAVB", value:"2020-B-0071-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : go1.15 (SUSE-SU-2020:3368-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for go1.15 fixes the following issues :

go1.15.5 (released 2020-11-12) includes security fixes to the cmd/go
and math/big packages.

  - go#42553 math/big: panic during recursive division of
    very large numbers (bsc#1178750 CVE-2020-28362)

  - go#42560 cmd/go: arbitrary code can be injected into cgo
    generated files (bsc#1178752 CVE-2020-28367)

  - go#42557 cmd/go: improper validation of cgo flags can
    lead to remote code execution at build time (bsc#1178753
    CVE-2020-28366)

  - go#42169 cmd/compile, runtime, reflect: pointers to
    go:notinheap types must be stored indirectly in
    interfaces

  - go#42151 cmd/cgo: opaque struct pointers are broken
    since Go 1.15.3

  - go#42138 time: Location interprets wrong timezone (DST)
    with slim zoneinfo

  - go#42113 x/net/http2: the first write error on a
    connection will cause all subsequent write requests to
    fail blindly

  - go#41914 net/http: request.Clone doesn't deep copy
    TransferEncoding

  - go#41704 runtime: macOS syscall.Exec can get SIGILL due
    to preemption signal

  - go#41463 compress/flate: deflatefast produces corrupted
    output

  - go#41387 x/net/http2: connection-level flow control not
    returned if stream errors, causes server hang

  - go#40974 cmd/link: sectionForAddress(0xA9D67F) address
    not in any section file

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28362/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28366/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28367/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203368-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04fb9f7d");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP2-2020-3368=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-3368=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28367");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.15-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES15", sp:"1", reference:"go1.15-1.15.5-1.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"go1.15-doc-1.15.5-1.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"go1.15-1.15.5-1.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"go1.15-doc-1.15.5-1.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"go1.15-1.15.5-1.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"go1.15-doc-1.15.5-1.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"go1.15-1.15.5-1.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"go1.15-doc-1.15.5-1.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "go1.15");
}
