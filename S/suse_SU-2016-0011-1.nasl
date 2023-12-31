#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0011-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87858);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-9732", "CVE-2015-4467", "CVE-2015-4468", "CVE-2015-4469", "CVE-2015-4470", "CVE-2015-4471", "CVE-2015-4472");
  script_bugtraq_id(72474, 72486, 72487, 72488, 72490, 72492);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libmspack (SUSE-SU-2016:0011-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libmspack was updated to fix security issues.

These security issues were fixed :

  - CVE-2014-9732: The cabd_extract function in cabd.c in
    libmspack did not properly maintain decompression
    callbacks in certain cases where an invalid file follows
    a valid file, which allowed remote attackers to cause a
    denial of service (NULL pointer dereference and
    application crash) via a crafted CAB archive
    (bnc#934524).

  - CVE-2015-4467: The chmd_init_decomp function in chmd.c
    in libmspack did not properly validate the reset
    interval, which allowed remote attackers to cause a
    denial of service (divide-by-zero error and application
    crash) via a crafted CHM file (bnc#934525).

  - CVE-2015-4468: Multiple integer overflows in the
    search_chunk function in chmd.c in libmspack allowed
    remote attackers to cause a denial of service (buffer
    over-read and application crash) via a crafted CHM file
    (bnc#934526).

  - CVE-2015-4469: The chmd_read_headers function in chmd.c
    in libmspack did not validate name lengths, which
    allowed remote attackers to cause a denial of service
    (buffer over-read and application crash) via a crafted
    CHM file (bnc#934526).

  - CVE-2015-4470: Off-by-one error in the inflate function
    in mszipd.c in libmspack allowed remote attackers to
    cause a denial of service (buffer over-read and
    application crash) via a crafted CAB archive
    (bnc#934527).

  - CVE-2015-4471: Off-by-one error in the lzxd_decompress
    function in lzxd.c in libmspack allowed remote attackers
    to cause a denial of service (buffer under-read and
    application crash) via a crafted CAB archive
    (bnc#934528).

  - CVE-2015-4472: Off-by-one error in the READ_ENCINT macro
    in chmd.c in libmspack allowed remote attackers to cause
    a denial of service (application crash) or possibly have
    unspecified other impact via a crafted CHM file
    (bnc#934529).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=934524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=934525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=934526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=934527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=934528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=934529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9732/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4467/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4468/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4469/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4470/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4471/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4472/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160011-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f9e4053"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-2=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-2=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-2=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-2=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-2=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-2=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmspack-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmspack0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmspack0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/04");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libmspack-debugsource-0.4-14.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libmspack0-0.4-14.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libmspack0-debuginfo-0.4-14.4")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmspack-debugsource-0.4-14.4")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmspack0-0.4-14.4")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmspack0-debuginfo-0.4-14.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmspack-debugsource-0.4-14.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmspack0-0.4-14.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmspack0-debuginfo-0.4-14.4")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmspack-debugsource-0.4-14.4")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmspack0-0.4-14.4")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmspack0-debuginfo-0.4-14.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmspack");
}
