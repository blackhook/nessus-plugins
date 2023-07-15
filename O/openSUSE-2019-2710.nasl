#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2710.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(132516);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/02");

  script_cve_id("CVE-2018-12207", "CVE-2019-11135");

  script_name(english:"openSUSE Security Update : spectre-meltdown-checker (openSUSE-2019-2710)");
  script_summary(english:"Check for the openSUSE-2019-2710 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for spectre-meltdown-checker fixes the following issues :

  - feat: implement TAA detection (CVE-2019-11135
    bsc#1139073)

  - feat: implement MCEPSC / iTLB Multihit detection
    (CVE-2018-12207 bsc#1117665)

  - feat: taa: add TSX_CTRL MSR detection in hardware info

  - feat: fwdb: use both Intel GitHub repo and MCEdb to
    build our firmware version database

  - feat: use --live with --kernel/--config/--map to
    override file detection in live mode

  - enh: rework the vuln logic of MDS with --paranoid (fixes
    #307)

  - enh: explain that Enhanced IBRS is better for
    performance than classic IBRS

  - enh: kernel: autodetect customized arch kernels from
    cmdline

  - enh: kernel decompression: better tolerance against
    missing tools

  - enh: mock: implement reading from /proc/cmdline

  - fix: variant3a: Silvermont CPUs are not vulnerable to
    variant 3a

  - fix: lockdown: detect Red Hat locked down kernels
    (impacts MSR writes)

  - fix: lockdown: detect locked down mode in vanilla 5.4+
    kernels

  - fix: sgx: on locked down kernels, fallback to CPUID bit
    for detection

  - fix: fwdb: builtin version takes precedence if the local
    cached version is older

  - fix: pteinv: don't check kernel image if not available

  - fix: silence useless error from grep (fixes #322)

  - fix: msr: fix msr module detection under Ubuntu 19.10
    (fixes #316)

  - fix: mocking value for read_msr

  - chore: rename mcedb cmdline parameters to fwdb, and
    change db version scheme

  - chore: fwdb: update to v130.20191104+i20191027

  - chore: add GitHub check workflow

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139073"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spectre-meltdown-checker package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11135");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spectre-meltdown-checker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"spectre-meltdown-checker-0.43-lp151.3.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spectre-meltdown-checker");
}
