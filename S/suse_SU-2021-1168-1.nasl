#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1168-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(148502);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/16");

  script_cve_id("CVE-2019-15945", "CVE-2019-15946", "CVE-2019-19479", "CVE-2019-19480", "CVE-2019-20792", "CVE-2020-26570", "CVE-2020-26571", "CVE-2020-26572");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : opensc (SUSE-SU-2021:1168-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opensc fixes the following issues :

CVE-2019-15945: Fixed an out-of-bounds access of an ASN.1 Bitstring in
decode_bit_string (bsc#1149746).

CVE-2019-15946: Fixed an out-of-bounds access of an ASN.1 Octet string
in asn1_decode_entry (bsc#1149747)

CVE-2019-19479: Fixed an incorrect read operation during parsing of a
SETCOS file attribute (bsc#1158256)

CVE-2019-19480: Fixed an improper free operation in
sc_pkcs15_decode_prkdf_entry (bsc#1158307).

CVE-2019-20792: Fixed a double free in coolkey_free_private_data
(bsc#1170809).

CVE-2020-26570: Fixed a buffer overflow in sc_oberthur_read_file
(bsc#1177364).

CVE-2020-26571: Fixed a stack-based buffer overflow in gemsafe GPK
smart card software driver (bsc#1177380)

CVE-2020-26572: Fixed a stack-based buffer overflow in tcos_decipher
(bsc#1177378).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1170809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15945/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15946/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19479/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19480/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-20792/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-26570/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-26571/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-26572/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211168-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c3f8d54"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2021-1168=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1168=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:opensc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:opensc-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"3", reference:"opensc-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"opensc-debuginfo-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"opensc-debugsource-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"opensc-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"opensc-debuginfo-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"opensc-debugsource-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"opensc-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"opensc-debuginfo-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"opensc-debugsource-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"opensc-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"opensc-debuginfo-0.19.0-3.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"opensc-debugsource-0.19.0-3.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opensc");
}
