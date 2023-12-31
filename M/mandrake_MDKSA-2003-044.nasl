#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:044. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14028);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2003-0196", "CVE-2003-0201");
  script_xref(name:"MDKSA", value:"2003:044");

  script_name(english:"Mandrake Linux Security Advisory : samba (MDKSA-2003:044)");
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
"An exploitable buffer overflow was discovered in the Samba server that
can lead to an anonymous remote root compromise. The Samba Team also
discovered some potential overflows during an internal code audit
which was done in response to the previously noted buffer overflow
problem.

All versions of Samba prior to 2.2.8a are vulnerable. The provided
updates contain a patch from the Samba Team to correct the issue.

An exploit is known to exist and all Mandrake Linux users are
encouraged to upgrade immediately."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba trans2open Overflow (Solaris SPARC)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss_wins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"nss_wins-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-client-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-common-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-doc-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-server-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-swat-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-winbind-2.2.7a-9.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"nss_wins-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-client-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-common-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-doc-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-server-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-swat-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-winbind-2.2.7a-9.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"nss_wins-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"samba-client-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"samba-common-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"samba-doc-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"samba-server-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"samba-swat-2.2.7a-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"samba-winbind-2.2.7a-9.2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
