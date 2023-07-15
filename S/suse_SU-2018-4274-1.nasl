#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:4274-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119937);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-8610", "CVE-2018-0734", "CVE-2018-5407");

  script_name(english:"SUSE SLES11 Security Update : openssl (SUSE-SU-2018:4274-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes the following issues :

Security issues fixed :

CVE-2018-0734: Fixed timing vulnerability in DSA signature generation
(bsc#1113652).

CVE-2018-5407: Fixed elliptic curve scalar multiplication timing
attack defenses (bsc#1113534).

CVE-2016-8610: Adjusted current fix and add missing error string
(bsc#1110018).

Fixed the 'One and Done' side-channel attack on RSA (bsc#1104789).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8610/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-0734/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5407/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20184274-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3e8ebe5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Studio Onsite 1.3:zypper in -t patch slestso13-openssl-13918=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-openssl-13918=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-openssl-13918=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-openssl-13918=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-openssl-13918=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-openssl-13918=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-openssl-13918=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0734");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl0_9_8-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libopenssl0_9_8-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libopenssl0_9_8-hmac-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssl-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssl-doc-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libopenssl-devel-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libopenssl0_9_8-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libopenssl0_9_8-hmac-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssl-0.9.8j-0.106.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssl-doc-0.9.8j-0.106.18.1")) flag++;


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
