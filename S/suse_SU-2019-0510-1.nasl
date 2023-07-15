#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0510-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122530);
  script_version("1.3");
  script_cvs_date("Date: 2020/02/07");

  script_cve_id("CVE-2016-7837", "CVE-2016-9800", "CVE-2016-9801", "CVE-2016-9804", "CVE-2016-9918", "CVE-2017-1000250");

  script_name(english:"SUSE SLES12 Security Update : bluez (SUSE-SU-2019:0510-1) (BlueBorne)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bluez fixes the following issues :

Security issues fixed :

CVE-2016-7837: Fixed possible buffer overflow, make sure we don't
write past the end of the array.(bsc#1026652)

CVE-2016-9800: Fix hcidump memory leak in pin_code_reply_dump()
(bsc#1013721).

CVE-2016-9801: Fixed a buffer overflow in set_ext_ctrl function
(bsc#1013732)

CVE-2016-9804: Fix hcidump buffer overflow in commands_dump()
(bsc#1013877).

CVE-2016-9918: Fixed an out-of-bounds read in packet_hexdump()
(bsc#1015173)

CVE-2017-1000250: Fixed a information leak in SDP (part of the
recently published BlueBorne vulnerabilities) (bsc#1057342)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1015173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1026652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7837/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9800/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9801/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9804/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9918/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000250/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190510-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69fdcf82"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2019-510=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-510=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2019-510=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7837");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bluez-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bluez-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libbluetooth3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libbluetooth3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"bluez-5.13-3.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"bluez-debuginfo-5.13-3.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"bluez-debugsource-5.13-3.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libbluetooth3-5.13-3.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libbluetooth3-debuginfo-5.13-3.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"bluez-5.13-3.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"bluez-debuginfo-5.13-3.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"bluez-debugsource-5.13-3.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libbluetooth3-5.13-3.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libbluetooth3-debuginfo-5.13-3.10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez");
}
