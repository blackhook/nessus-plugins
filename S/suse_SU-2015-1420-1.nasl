#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1420-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85597);
  script_version("2.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-8127", "CVE-2014-8128", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9655");
  script_bugtraq_id(72323, 72326, 72352, 72353, 73441);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : tiff (SUSE-SU-2015:1420-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"tiff was updated to fix six security issues found by fuzzing
initiatives.

These security issues were fixed :

  - CVE-2014-8127: Out-of-bounds write (bnc#914890).

  - CVE-2014-8128: Out-of-bounds write (bnc#914890).

  - CVE-2014-8129: Out-of-bounds write (bnc#914890).

  - CVE-2014-8130: Out-of-bounds write (bnc#914890).

  - CVE-2014-9655: Access of uninitialized memory
    (bnc#916927).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=914890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=916927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8127/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8128/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8129/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8130/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9655/"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151420-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f956b3a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-tiff-12040=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-tiff-12040=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-tiff-12040=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-tiff-12040=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-tiff-12040=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-tiff-12040=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-tiff-12040=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-tiff-12040=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-tiff-12040=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libtiff3-32bit-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libtiff3-32bit-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libtiff3-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"tiff-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libtiff3-32bit-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libtiff3-32bit-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libtiff3-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"tiff-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libtiff3-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libtiff3-32bit-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libtiff3-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libtiff3-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libtiff3-32bit-3.8.2-141.160.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libtiff3-3.8.2-141.160.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tiff");
}
