#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0030-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87862);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");
  script_bugtraq_id(75570);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : libxml2 (SUSE-SU-2016:0030-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues :

  - CVE-2015-1819 Enforce the reader to run in constant
    memory [bnc#928193]

  - CVE-2015-7941 Fix out of bound read with crafted xml
    input by stopping parsing on entities boundaries errors
    [bnc#951734]

  - CVE-2015-7942 Fix another variation of overflow in
    Conditional sections [bnc#951735]

  - CVE-2015-8241 Avoid extra processing of MarkupDecl when
    EOF [bnc#956018]

  - CVE-2015-8242 Buffer overead with HTML parser in push
    mode [bnc#956021]

  - CVE-2015-8317 Return if the encoding declaration is
    broken or encoding conversion failed [bnc#956260]

  - CVE-2015-5312 Fix another entity expansion issue
    [bnc#957105]

  - CVE-2015-7497 Avoid an heap buffer overflow in
    xmlDictComputeFastQKey [bnc#957106]

  - CVE-2015-7498 Processes entities after encoding
    conversion failures [bnc#957107]

  - CVE-2015-7499 Add xmlHaltParser() to stop the parser /
    Detect incoherency on GROW [bnc#957109]

  - CVE-2015-7500 Fix memory access error due to incorrect
    entities boundaries [bnc#957110]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=928193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1819/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5312/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7497/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7498/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7499/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7500/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7941/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7942/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8241/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8242/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8317/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160030-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e3022a8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-libxml2-20151221-12298=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-libxml2-20151221-12298=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-libxml2-20151221-12298=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-libxml2-20151221-12298=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-libxml2-20151221-12298=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-libxml2-20151221-12298=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-libxml2-20151221-12298=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-libxml2-20151221-12298=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-libxml2-20151221-12298=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libxml2-32bit-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libxml2-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libxml2-doc-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libxml2-python-2.7.6-0.34.4")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libxml2-32bit-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libxml2-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libxml2-doc-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libxml2-python-2.7.6-0.34.4")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libxml2-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libxml2-python-2.7.6-0.34.4")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libxml2-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libxml2-python-2.7.6-0.34.4")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libxml2-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libxml2-python-2.7.6-0.34.4")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libxml2-2.7.6-0.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libxml2-python-2.7.6-0.34.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
