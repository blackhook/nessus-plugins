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
  script_id(71425);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-1418");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : krb5 (SAT Patch Numbers 8533 / 8534)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for krb5 fixes the following security issue :

  - If a KDC serves multiple realms, certain requests could
    cause setup_server_realm() to dereference a NULL
    pointer, crashing the KDC. (CVE-2013-1418)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1418.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8533 / 8534 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-apps-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-apps-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"krb5-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"krb5-client-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"krb5-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"krb5-32bit-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"krb5-client-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"krb5-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"krb5-client-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"krb5-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"krb5-32bit-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"krb5-client-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"krb5-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"krb5-apps-clients-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"krb5-apps-servers-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"krb5-client-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"krb5-doc-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"krb5-plugin-kdb-ldap-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"krb5-plugin-preauth-pkinit-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"krb5-server-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"krb5-32bit-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"krb5-32bit-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-apps-clients-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-apps-servers-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-client-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-doc-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-plugin-kdb-ldap-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-plugin-preauth-pkinit-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-server-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"krb5-32bit-1.6.3-133.49.58.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"krb5-32bit-1.6.3-133.49.58.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
