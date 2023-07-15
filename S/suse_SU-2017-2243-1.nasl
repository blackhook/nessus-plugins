#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2243-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102728);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-10978", "CVE-2017-10983", "CVE-2017-10984", "CVE-2017-10985", "CVE-2017-10987", "CVE-2017-10988");

  script_name(english:"SUSE SLES12 Security Update : freeradius-server (SUSE-SU-2017:2243-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for freeradius fixes the following issues: Security issues
fixed :

  - CVE-2017-10988: Decode 'signed' attributes correctly.
    (bnc#1049086)

  - CVE-2017-10987: Check for option overflowing the packet.
    (bnc#1049086)

  - CVE-2017-10985: Fix infinite loop and memory exhaustion
    with 'concat' attributes. (bnc#1049086)

  - CVE-2017-10984: Fix write overflow in data2vp_wimax().
    (bnc#1049086)

  - CVE-2017-10983: Fix read overflow when decoding option
    63. (bnc#1049086)

  - CVE-2017-10978: Fix read / write overflow in
    make_secret(). (bnc#1049086)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10978/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10983/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10984/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10985/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10987/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10988/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172243-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88eaae02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1373=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1373=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1373=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/24");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-debuginfo-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-debugsource-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-doc-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-krb5-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-krb5-debuginfo-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-ldap-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-ldap-debuginfo-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-libs-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-libs-debuginfo-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-mysql-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-mysql-debuginfo-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-perl-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-perl-debuginfo-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-postgresql-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-postgresql-debuginfo-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-python-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-python-debuginfo-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-sqlite-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-sqlite-debuginfo-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-utils-3.0.3-17.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freeradius-server-utils-debuginfo-3.0.3-17.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius-server");
}
