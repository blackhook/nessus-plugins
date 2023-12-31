#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:241. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50820);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2010-3999");
  script_bugtraq_id(44563);
  script_xref(name:"MDVSA", value:"2010:241");

  script_name(english:"Mandriva Linux Security Advisory : gnucash (MDVSA-2010:241)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was discovered and corrected in gnucash :

gnc-test-env in GnuCash 2.3.15 and earlier places a zero-length
directory name in the LD_LIBRARY_PATH, which allows local users to
gain privileges via a Trojan horse shared library in the current
working directory (CVE-2010-3999).

The affected /usr/bin/gnc-test-env file has been removed to mitigate
the CVE-2010-3999 vulnerability as gnc-test-env is only used for tests
and while building gnucash.

Additionally for Mandriva 2010.1 gnucash-2.2.9 was not compatible with
guile. This update adapts gnucash to the new API of guile."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnucash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnucash-hbci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnucash-ofx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnucash-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gnucash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gnucash0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgnucash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgnucash0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"MDK2010.0", reference:"gnucash-2.2.9-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnucash-hbci-2.2.9-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnucash-ofx-2.2.9-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnucash-sql-2.2.9-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64gnucash-devel-2.2.9-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64gnucash0-2.2.9-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libgnucash-devel-2.2.9-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libgnucash0-2.2.9-4.1mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"gnucash-2.2.9-8.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnucash-hbci-2.2.9-8.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnucash-ofx-2.2.9-8.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnucash-sql-2.2.9-8.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64gnucash-devel-2.2.9-8.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64gnucash0-2.2.9-8.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libgnucash-devel-2.2.9-8.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libgnucash0-2.2.9-8.1mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
