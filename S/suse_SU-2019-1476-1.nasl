#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1476-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(125874);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-16838");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : sssd (SUSE-SU-2019:1476-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for sssd fixes the following issues :

Security issue fixed :

CVE-2018-16838: Fixed an authentication bypass related to the Group
Policy Objects implementation (bsc#1124194).

Non-security issues fixed: Allow defaults sudoRole without sudoUser
attribute (bsc#1135247)

Missing GPOs directory could have led to login problems (bsc#1132879)

Fix a crash by adding a netgroup counter to struct nss_enum_index
(bsc#1132657)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16838/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191476-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76470eba"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-1476=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1476=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-1476=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-1476=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnfsidmap-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnfsidmap-sss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_certmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_certmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_nss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_nss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_simpleifp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_simpleifp0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ipa_hbac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-sss-murmur-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-sss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-sss_nss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-sssd-config-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-dbus-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-wbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-wbclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-wbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-winbind-idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"sssd-32bit-1.16.1-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"sssd-32bit-debuginfo-1.16.1-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libipa_hbac-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libipa_hbac0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libipa_hbac0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnfsidmap-sss-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnfsidmap-sss-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_certmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_certmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_certmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_idmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_idmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_idmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_nss_idmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_nss_idmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_nss_idmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_simpleifp-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_simpleifp0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsss_simpleifp0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-ipa_hbac-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-ipa_hbac-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-sss-murmur-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-sss-murmur-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-sss_nss_idmap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-sss_nss_idmap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-sssd-config-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-sssd-config-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-ad-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-ad-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-dbus-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-dbus-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-debugsource-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-ipa-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-ipa-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-krb5-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-krb5-common-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-krb5-common-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-krb5-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-ldap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-ldap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-proxy-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-proxy-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-tools-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-tools-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-wbclient-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-wbclient-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-wbclient-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-winbind-idmap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sssd-winbind-idmap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"sssd-32bit-1.16.1-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"sssd-32bit-debuginfo-1.16.1-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libipa_hbac-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libipa_hbac0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libipa_hbac0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnfsidmap-sss-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnfsidmap-sss-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_certmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_certmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_certmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_idmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_idmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_idmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_nss_idmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_nss_idmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_nss_idmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_simpleifp-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_simpleifp0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsss_simpleifp0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-ipa_hbac-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-ipa_hbac-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-sss-murmur-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-sss-murmur-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-sss_nss_idmap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-sss_nss_idmap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-sssd-config-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-sssd-config-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-ad-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-ad-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-dbus-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-dbus-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-debugsource-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-ipa-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-ipa-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-krb5-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-krb5-common-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-krb5-common-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-krb5-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-ldap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-ldap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-proxy-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-proxy-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-tools-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-tools-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-wbclient-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-wbclient-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-wbclient-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-winbind-idmap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sssd-winbind-idmap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"sssd-32bit-1.16.1-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"sssd-32bit-debuginfo-1.16.1-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libipa_hbac-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libipa_hbac0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libipa_hbac0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnfsidmap-sss-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnfsidmap-sss-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_certmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_certmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_certmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_idmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_idmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_idmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_nss_idmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_nss_idmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_nss_idmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_simpleifp-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_simpleifp0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsss_simpleifp0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-ipa_hbac-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-ipa_hbac-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-sss-murmur-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-sss-murmur-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-sss_nss_idmap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-sss_nss_idmap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-sssd-config-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-sssd-config-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-ad-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-ad-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-dbus-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-dbus-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-debugsource-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-ipa-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-ipa-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-krb5-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-krb5-common-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-krb5-common-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-krb5-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-ldap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-ldap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-proxy-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-proxy-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-tools-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-tools-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-wbclient-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-wbclient-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-wbclient-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-winbind-idmap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sssd-winbind-idmap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"sssd-32bit-1.16.1-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"sssd-32bit-debuginfo-1.16.1-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libipa_hbac-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libipa_hbac0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libipa_hbac0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnfsidmap-sss-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnfsidmap-sss-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_certmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_certmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_certmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_idmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_idmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_idmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_nss_idmap-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_nss_idmap0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_nss_idmap0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_simpleifp-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_simpleifp0-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsss_simpleifp0-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-ipa_hbac-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-ipa_hbac-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-sss-murmur-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-sss-murmur-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-sss_nss_idmap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-sss_nss_idmap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-sssd-config-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-sssd-config-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-ad-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-ad-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-dbus-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-dbus-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-debugsource-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-ipa-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-ipa-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-krb5-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-krb5-common-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-krb5-common-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-krb5-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-ldap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-ldap-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-proxy-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-proxy-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-tools-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-tools-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-wbclient-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-wbclient-debuginfo-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-wbclient-devel-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-winbind-idmap-1.16.1-3.24.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sssd-winbind-idmap-debuginfo-1.16.1-3.24.6")) flag++;


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
