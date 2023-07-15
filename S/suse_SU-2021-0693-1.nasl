#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0693-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(147134);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/08");

  script_cve_id("CVE-2020-36221", "CVE-2020-36222", "CVE-2020-36223", "CVE-2020-36224", "CVE-2020-36225", "CVE-2020-36226", "CVE-2020-36227", "CVE-2020-36228", "CVE-2020-36229", "CVE-2020-36230", "CVE-2021-27212");
  script_xref(name:"IAVB", value:"2021-B-0014");

  script_name(english:"SUSE SLES12 Security Update : openldap2 (SUSE-SU-2021:0693-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openldap2 fixes the following issues :

bsc#1182408 CVE-2020-36230 - an assertion failure in slapd in the
X.509 DN parsing in decode.c ber_next_element, resulting in denial of
service.

bsc#1182411 CVE-2020-36229 - ldap_X509dn2bv crash in the X.509 DN
parsing in ad_keystring, resulting in denial of service.

bsc#1182412 CVE-2020-36228 - integer underflow leading to crash in the
Certificate List Exact Assertion processing, resulting in denial of
service.

bsc#1182413 CVE-2020-36227 - infinite loop in slapd with the
cancel_extop Cancel operation, resulting in denial of service.

bsc#1182416 CVE-2020-36225 - double free and slapd crash in the
saslAuthzTo processing, resulting in denial of service.

bsc#1182417 CVE-2020-36224 - invalid pointer free and slapd crash in
the saslAuthzTo processing, resulting in denial of service.

bsc#1182415 CVE-2020-36226 - memch->bv_len miscalculation and slapd
crash in the saslAuthzTo processing, resulting in denial of service.

bsc#1182419 CVE-2020-36222 - assertion failure in slapd in the
saslAuthzTo validation, resulting in denial of service.

bsc#1182420 CVE-2020-36221 - slapd crashes in the Certificate Exact
Assertion processing, resulting in denial of service (schema_init.c
serialNumberAndIssuerCheck).

bsc#1182418 CVE-2020-36223 - slapd crash in the Values Return Filter
control handling, resulting in denial of service (double free and
out-of-bounds read).

bsc#1182279 CVE-2021-27212 - an assertion failure in slapd can occur
in the issuerAndThisUpdateCheck function via a crafted packet,
resulting in a denial of service (daemon exit) via a short timestamp.
This is related to schema_init.c and checkTime.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36221/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36222/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36223/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36224/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36225/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36226/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36227/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36228/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36229/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36230/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-27212/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210693-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d6276bc"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2021-693=1

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2021-693=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2021-693=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2021-693=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2021-693=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2021-693=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2021-693=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2021-693=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2021-693=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-693=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2021-693=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2021-693=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2021-693=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2021-693=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2021-693=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2021-693=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-back-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-back-meta-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-ppolicy-check-password");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-ppolicy-check-password-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libldap-2_4-2-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libldap-2_4-2-32bit-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libldap-2_4-2-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libldap-2_4-2-debuginfo-32bit-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openldap2-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openldap2-back-meta-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openldap2-back-meta-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openldap2-client-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openldap2-client-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openldap2-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openldap2-debugsource-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openldap2-ppolicy-check-password-1.2-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openldap2-ppolicy-check-password-debuginfo-1.2-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libldap-2_4-2-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libldap-2_4-2-32bit-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libldap-2_4-2-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libldap-2_4-2-debuginfo-32bit-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openldap2-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openldap2-back-meta-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openldap2-back-meta-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openldap2-client-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openldap2-client-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openldap2-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openldap2-debugsource-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openldap2-ppolicy-check-password-1.2-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openldap2-ppolicy-check-password-debuginfo-1.2-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libldap-2_4-2-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libldap-2_4-2-32bit-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libldap-2_4-2-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libldap-2_4-2-debuginfo-32bit-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openldap2-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openldap2-back-meta-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openldap2-back-meta-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openldap2-client-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openldap2-client-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openldap2-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openldap2-debugsource-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openldap2-ppolicy-check-password-1.2-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openldap2-ppolicy-check-password-debuginfo-1.2-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libldap-2_4-2-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libldap-2_4-2-32bit-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libldap-2_4-2-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libldap-2_4-2-debuginfo-32bit-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"openldap2-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"openldap2-back-meta-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"openldap2-back-meta-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"openldap2-client-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"openldap2-client-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"openldap2-debuginfo-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"openldap2-debugsource-2.4.41-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"openldap2-ppolicy-check-password-1.2-18.83.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"openldap2-ppolicy-check-password-debuginfo-1.2-18.83.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap2");
}
