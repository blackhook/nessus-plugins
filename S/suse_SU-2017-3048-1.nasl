#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3048-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104777);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9621", "CVE-2014-9653");
  script_bugtraq_id(71692, 71700, 71714, 71715, 72516);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : file (SUSE-SU-2017:3048-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The GNU file utility was updated to version 5.22. Security issues
fixed :

  - CVE-2014-9621: The ELF parser in file allowed remote
    attackers to cause a denial of service via a long
    string. (bsc#913650)

  - CVE-2014-9620: The ELF parser in file allowed remote
    attackers to cause a denial of service via a large
    number of notes. (bsc#913651)

  - CVE-2014-9653: readelf.c in file did not consider that
    pread calls sometimes read only a subset of the
    available data, which allows remote attackers to cause a
    denial of service (uninitialized memory access) or
    possibly have unspecified other impact via a crafted ELF
    file. (bsc#917152)

  - CVE-2014-8116: The ELF parser (readelf.c) in file
    allowed remote attackers to cause a denial of service
    (CPU consumption or crash) via a large number of (1)
    program or (2) section headers or (3) invalid
    capabilities. (bsc#910253)

  - CVE-2014-8117: softmagic.c in file did not properly
    limit recursion, which allowed remote attackers to cause
    a denial of service (CPU consumption or crash) via
    unspecified vectors. (bsc#910253) Version update to file
    version 5.22

  - add indirect relative for TIFF/Exif

  - restructure elf note printing to avoid repeated messages

  - add note limit, suggested by Alexander Cherepanov

  - Bail out on partial pread()'s (Alexander Cherepanov)

  - Fix incorrect bounds check in file_printable (Alexander
    Cherepanov)

  - PR/405: ignore SIGPIPE from uncompress programs

  - change printable -> file_printable and use it in more
    places for safety

  - in ELF, instead of '(uses dynamic libraries)' when
    PT_INTERP is present print the interpreter name. Version
    update to file version 5.21

  - there was an incorrect free in magic_load_buffers()

  - there was an out of bounds read for some pascal strings

  - there was a memory leak in magic lists

  - don't interpret strings printed from files using the
    current locale, convert them to ascii format first.

  - there was an out of bounds read in elf note reads Update
    to file version 5.20

  - recognize encrypted CDF documents

  - add magic_load_buffers from Brooks Davis

  - add thumbs.db support

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1009966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=910252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=910253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=913650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=913651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=996511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8116/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8117/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9620/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9621/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9653/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173048-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac727fb8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1881=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1881=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1881=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1881=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1881=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1881=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1881=1

SUSE Container as a Service Platform ALL:zypper in -t patch
SUSE-CAASP-ALL-2017-1881=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2017-1881=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmagic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmagic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");
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
if (rpm_check(release:"SLES12", sp:"3", reference:"file-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"file-debuginfo-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"file-debugsource-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"file-magic-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libmagic1-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libmagic1-debuginfo-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libmagic1-32bit-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libmagic1-debuginfo-32bit-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"file-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"file-debuginfo-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"file-debugsource-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"file-magic-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libmagic1-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libmagic1-debuginfo-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libmagic1-32bit-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libmagic1-debuginfo-32bit-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"file-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"file-debuginfo-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"file-debugsource-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"file-magic-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmagic1-32bit-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmagic1-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmagic1-debuginfo-32bit-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmagic1-debuginfo-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"file-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"file-debuginfo-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"file-debugsource-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"file-magic-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libmagic1-32bit-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libmagic1-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libmagic1-debuginfo-32bit-5.22-10.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libmagic1-debuginfo-5.22-10.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file");
}
