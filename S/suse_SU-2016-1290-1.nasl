#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1290-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91158);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-0702", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2108", "CVE-2016-2109");

  script_name(english:"SUSE SLES11 Security Update : openssl (SUSE-SU-2016:1290-1)");
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

  - CVE-2016-2108: Memory corruption in the ASN.1 encoder
    (bsc#977617)

  - CVE-2016-2105: EVP_EncodeUpdate overflow (bsc#977614)

  - CVE-2016-2106: EVP_EncryptUpdate overflow (bsc#977615)

  - CVE-2016-2109: ASN.1 BIO excessive memory allocation
    (bsc#976942)

  - CVE-2016-0702: Side channel attack on modular
    exponentiation 'CacheBleed' (bsc#968050)

Bugs fixed :

  - fate#320304: build 32bit devel package

  - bsc#976943: Fix buffer overrun in ASN1_parse

  - bsc#973223: allow weak DH groups, vulnerable to the
    logjam attack, when environment variable
    OPENSSL_ALLOW_LOGJAM_ATTACK is set

  - bsc#889013: Rename README.SuSE to the new spelling

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=889013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=976942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=976943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=977614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=977615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=977617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0702/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2105/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2106/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2108/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2109/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161290-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66635c17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Studio Onsite 1.3 :

zypper in -t patch slestso13-openssl-12557=1

SUSE OpenStack Cloud 5 :

zypper in -t patch sleclo50sp3-openssl-12557=1

SUSE Manager Proxy 2.1 :

zypper in -t patch slemap21-openssl-12557=1

SUSE Manager 2.1 :

zypper in -t patch sleman21-openssl-12557=1

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-openssl-12557=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-openssl-12557=1

SUSE Linux Enterprise Server 11-SP3-LTSS :

zypper in -t patch slessp3-openssl-12557=1

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-openssl-12557=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-openssl-12557=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-openssl-12557=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-openssl-12557=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl0_9_8-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libopenssl0_9_8-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libopenssl0_9_8-hmac-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssl-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssl-doc-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libopenssl-devel-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libopenssl0_9_8-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libopenssl0_9_8-hmac-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssl-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssl-doc-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libopenssl-devel-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libopenssl0_9_8-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libopenssl0_9_8-hmac-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"openssl-0.9.8j-0.97.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"openssl-doc-0.9.8j-0.97.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
