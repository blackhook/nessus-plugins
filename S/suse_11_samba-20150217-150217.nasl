#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81508);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-0240");

  script_name(english:"SuSE 11.3 Security Update : Samba (SAT Patch Number 10321)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Samba has been updated to fix one security issue :

  - Don't call talloc_free on an uninitialized pointer
    (bnc#917376). Additionally, these non-security issues
    have been fixed :. (CVE-2015-0240)

  - Realign the winbind request structure following
    require_membership_of field expansion. (bnc#913001)

  - Reuse connections derived from DFS referrals (bso#10123,
    fate#316512).

  - Set domain/workgroup based on authentication callback
    value (bso#11059).

  - Fix spoolss error response marshalling (bso#10984).

  - Fix spoolss EnumJobs and GetJob responses (bso#10905,
    bnc#898031).

  - Fix handling of bad EnumJobs levels (bso#10898).

  - Fix small memory-leak in the background print process;.
    (bnc#899558)

  - Prune idle or hung connections older than 'winbind
    request timeout' (bso#3204, bnc#872912)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=872912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=898031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=899558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=913001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=917376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0240.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10321.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libldb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libldb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtalloc2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtevent0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libldb1-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libsmbclient0-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libtalloc2-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libtdb1-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libtevent0-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libwbclient0-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"samba-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"samba-client-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"samba-doc-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"samba-krb-printing-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"samba-winbind-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libldb1-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libldb1-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsmbclient0-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libtalloc2-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libtalloc2-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libtdb1-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libtdb1-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libtevent0-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libtevent0-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libwbclient0-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"samba-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"samba-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"samba-client-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"samba-client-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"samba-doc-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"samba-krb-printing-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"samba-winbind-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"ldapsmb-1.34b-12.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libldb1-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libsmbclient0-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libtalloc2-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libtdb1-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libtevent0-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libwbclient0-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"samba-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"samba-client-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"samba-doc-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"samba-krb-printing-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"samba-winbind-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libsmbclient0-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libtalloc2-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libtdb1-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libtevent0-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libwbclient0-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"samba-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"samba-client-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"samba-winbind-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libtalloc2-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libtdb1-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libtevent0-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"samba-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"samba-client-32bit-3.6.3-0.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-0.56.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
