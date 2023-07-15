#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0585-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(107131);
  script_version("3.5");
  script_cvs_date("Date: 2019/09/10 13:51:47");

  script_cve_id("CVE-2017-12596", "CVE-2017-9110", "CVE-2017-9114");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openexr (SUSE-SU-2018:0585-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openexr fixes the following issues :

  - CVE-2017-9110: In OpenEXR, an invalid read of size 2 in
    the hufDecode function in ImfHuf.cpp could cause the
    application to crash. (bsc#1040107)

  - CVE-2017-9114: In OpenEXR, an invalid read of size 1 in
    the refill function in ImfFastHuf.cpp could cause the
    application to crash. (bsc#1040114)

  - CVE-2017-12596: In OpenEXR, a crafted image causes a
    heap-based buffer over-read in the hufDecode function in
    IlmImf/ImfHuf.cpp during exrmaketiled execution; it
    could have resulted in denial of service or possibly
    unspecified other impact. (bsc#1052522)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12596/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9110/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9114/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180585-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39eae8bf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2018-398=1

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2018-398=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-398=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-398=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-398=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-398=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-398=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-398=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2018-398=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImf-Imf_2_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImf-Imf_2_1-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImf-Imf_2_1-21-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openexr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openexr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openexr-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (rpm_check(release:"SLES12", sp:"3", reference:"libIlmImf-Imf_2_1-21-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libIlmImf-Imf_2_1-21-debuginfo-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openexr-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openexr-debuginfo-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openexr-debugsource-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libIlmImf-Imf_2_1-21-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libIlmImf-Imf_2_1-21-debuginfo-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openexr-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openexr-debuginfo-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openexr-debugsource-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-32bit-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-debuginfo-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-debuginfo-32bit-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openexr-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openexr-debuginfo-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openexr-debugsource-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-32bit-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-debuginfo-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-debuginfo-32bit-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"openexr-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"openexr-debuginfo-2.1.0-6.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"openexr-debugsource-2.1.0-6.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openexr");
}
