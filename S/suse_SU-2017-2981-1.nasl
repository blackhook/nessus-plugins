#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2981-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104530);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-3735");

  script_name(english:"SUSE SLES12 Security Update : openssl (SUSE-SU-2017:2981-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes the following issues: Security issues
fixed :

  - CVE-2017-3735: Malformed X.509 IPAdressFamily could
    cause OOB read (bsc#1056058)

  - adjust DEFAULT_SUSE to meet 1.0.2 and current state
    (bsc#1027908)

  - out of bounds read+crash in DES_fcrypt (bsc#1065363)

  - DEFAULT_SUSE cipher list is missing ECDHE-ECDSA ciphers
    (bsc#1055825)

  - Missing important ciphers in openssl 1.0.1i-47.1
    (bsc#990592) Bug fixes :

  - support alternate root ca chains (bsc#1032261)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=990592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3735/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172981-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35d8eec1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2017-1846=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2017-1846=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-1846=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-1.0.1i-54.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-debuginfo-1.0.1i-54.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-hmac-1.0.1i-54.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssl-1.0.1i-54.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssl-debuginfo-1.0.1i-54.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssl-debugsource-1.0.1i-54.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-32bit-1.0.1i-54.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-54.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-hmac-32bit-1.0.1i-54.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
