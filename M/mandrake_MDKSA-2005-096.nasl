#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:096. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18434);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-0109");
  script_xref(name:"MDKSA", value:"2005:096");

  script_name(english:"Mandrake Linux Security Advisory : openssl (MDKSA-2005:096)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Colin Percival reported a cache timing attack that could be used to
allow a malicious local user to gain portions of cryptographic keys
(CVE-2005-0109). The OpenSSL library has been patched to add a new
fixed-window mod_exp implementation as default for RSA, DSA, and DH
private key operations. The patch was designed to mitigate cache
timing and possibly related attacks."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.7-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.7-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64openssl0.9.7-0.9.7c-3.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64openssl0.9.7-devel-0.9.7c-3.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64openssl0.9.7-static-devel-0.9.7c-3.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libopenssl0.9.7-0.9.7c-3.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libopenssl0.9.7-devel-0.9.7c-3.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libopenssl0.9.7-static-devel-0.9.7c-3.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"openssl-0.9.7c-3.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64openssl0.9.7-0.9.7d-1.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64openssl0.9.7-devel-0.9.7d-1.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64openssl0.9.7-static-devel-0.9.7d-1.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libopenssl0.9.7-0.9.7d-1.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libopenssl0.9.7-devel-0.9.7d-1.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libopenssl0.9.7-static-devel-0.9.7d-1.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"openssl-0.9.7d-1.2.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64openssl0.9.7-0.9.7e-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64openssl0.9.7-devel-0.9.7e-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64openssl0.9.7-static-devel-0.9.7e-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libopenssl0.9.7-0.9.7e-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libopenssl0.9.7-devel-0.9.7e-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libopenssl0.9.7-static-devel-0.9.7e-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"openssl-0.9.7e-5.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
