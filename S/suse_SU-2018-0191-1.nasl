#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0191-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(106342);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/10 13:51:46");

  script_cve_id("CVE-2017-17935", "CVE-2017-5753", "CVE-2018-5334", "CVE-2018-5335", "CVE-2018-5336");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : wireshark (SUSE-SU-2018:0191-1) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark to version 2.2.12 fixes the following 
issues :

  - CVE-2018-5334: IxVeriWave file could crash (bsc#1075737)

  - CVE-2018-5335: WCP dissector could crash (bsc#1075738)

  - CVE-2018-5336: Multiple dissector crashes (bsc#1075739)

  - CVE-2017-17935: Incorrect handling of '\n' in
    file_read_line function could have lead to denial of
    service (bsc#1074171) This release no longer enables the
    Linux kernel BPF JIT compiler via the
    net.core.bpf_jit_enable sysctl, as this would make
    systems more vulnerable to Spectre variant 1
    CVE-2017-5753 - (bsc#1075748) Further bug fixes and
    updated protocol support as listed in:
    https://www.wireshark.org/docs/relnotes/wireshark-2.2.12
    .html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17935/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5334/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5335/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5336/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180191-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24f8b47a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.12.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-134=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-134=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-134=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-134=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-134=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-134=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2018-134=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwireshark8-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwireshark8-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwiretap6-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwiretap6-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwscodecs1-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwscodecs1-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwsutil7-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwsutil7-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-debugsource-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-gtk-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-gtk-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwireshark8-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwireshark8-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwiretap6-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwiretap6-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwscodecs1-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwscodecs1-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwsutil7-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwsutil7-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"wireshark-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"wireshark-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"wireshark-debugsource-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"wireshark-gtk-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"wireshark-gtk-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwireshark8-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwireshark8-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwiretap6-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwiretap6-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwscodecs1-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwscodecs1-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwsutil7-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwsutil7-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-debugsource-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-gtk-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-gtk-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwireshark8-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwireshark8-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwiretap6-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwiretap6-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwscodecs1-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwscodecs1-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwsutil7-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwsutil7-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-debuginfo-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-debugsource-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-gtk-2.2.12-48.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-gtk-debuginfo-2.2.12-48.18.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
