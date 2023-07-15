#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2937-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104430);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-12173");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : sssd (SUSE-SU-2017:2937-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for sssd provides the following fixes: Security issues
fixed :

  - CVE-2017-12173: Fixed unsanitized input when searching
    in local cache database (bsc#1061832). Non security
    issues fixed :

  - Fixed a segfault issue in
    ldap_rfc_2307_fallback_to_local_users. (bsc#1055123)

  - Install /var/lib/sss/mc directory to correct sssd cache
    invalidation behaviour. (bsc#1039567)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12173/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172937-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3344a2f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1823=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1823=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1823=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1823=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1823=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1823=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1823=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_nss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_nss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-sssd-config-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/07");
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
if (rpm_check(release:"SLES12", sp:"3", reference:"libipa_hbac0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libipa_hbac0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsss_idmap0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsss_idmap0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsss_nss_idmap0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsss_nss_idmap0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsss_sudo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsss_sudo-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-sssd-config-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-sssd-config-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-ad-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-ad-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-debugsource-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-ipa-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-ipa-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-krb5-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-krb5-common-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-krb5-common-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-krb5-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-ldap-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-ldap-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-proxy-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-proxy-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-tools-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-tools-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-32bit-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"sssd-debuginfo-32bit-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libipa_hbac0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libipa_hbac0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsss_idmap0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsss_idmap0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsss_sudo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsss_sudo-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-sssd-config-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-sssd-config-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-ad-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-ad-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-debugsource-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-ipa-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-ipa-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-krb5-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-krb5-common-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-krb5-common-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-krb5-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-ldap-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-ldap-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-proxy-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-proxy-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-tools-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-tools-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-32bit-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"sssd-debuginfo-32bit-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libipa_hbac0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libipa_hbac0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsss_idmap0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsss_idmap0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsss_nss_idmap0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsss_nss_idmap0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsss_sudo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsss_sudo-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-sssd-config-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-sssd-config-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-32bit-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-ad-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-ad-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-debuginfo-32bit-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-debugsource-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-ipa-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-ipa-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-krb5-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-krb5-common-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-krb5-common-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-krb5-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-ldap-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-ldap-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-proxy-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-proxy-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-tools-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"sssd-tools-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libipa_hbac0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libipa_hbac0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsss_idmap0-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsss_idmap0-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsss_sudo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsss_sudo-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"python-sssd-config-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"python-sssd-config-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-32bit-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-ad-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-ad-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-debuginfo-32bit-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-debugsource-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-ipa-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-ipa-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-krb5-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-krb5-common-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-krb5-common-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-krb5-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-ldap-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-ldap-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-proxy-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-proxy-debuginfo-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-tools-1.13.4-34.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"sssd-tools-debuginfo-1.13.4-34.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}
