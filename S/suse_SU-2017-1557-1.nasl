#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1557-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100780);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-9318", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050");

  script_name(english:"SUSE SLES11 Security Update : libxml2 (SUSE-SU-2017:1557-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libxml2 fixes the following issues: Security issues
fixed :

  - CVE-2017-9050: heap-based buffer overflow
    (xmlDictAddString func) [bsc#1039069, bsc#1039661]

  - CVE-2017-9049: heap-based buffer overflow
    (xmlDictComputeFastKey func) [bsc#1039066]

  - CVE-2017-9048: stack overflow vulnerability
    (xmlSnprintfElementContent func) [bsc#1039063]

  - CVE-2017-9047: stack overflow vulnerability
    (xmlSnprintfElementContent func) [bsc#1039064] A
    clarification for the previously released update: For
    CVE-2016-9318 we decided not to ship a fix since it can
    break existing setups. Please take appropriate actions
    if you parse untrusted XML files and use the new

-noxxe flag if possible (bnc#1010675, bnc#1013930).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9318/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9047/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9048/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9049/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9050/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171557-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b70a10e1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-libxml2-13143=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-libxml2-13143=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-libxml2-13143=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-libxml2-13143=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-libxml2-13143=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-libxml2-13143=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.69.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libxml2-32bit-2.7.6-0.69.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libxml2-2.7.6-0.69.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libxml2-doc-2.7.6-0.69.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libxml2-python-2.7.6-0.69.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.69.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libxml2-32bit-2.7.6-0.69.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libxml2-2.7.6-0.69.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libxml2-doc-2.7.6-0.69.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libxml2-python-2.7.6-0.69.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
