#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:063. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17669);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-0085");
  script_xref(name:"MDKSA", value:"2005:063");

  script_name(english:"Mandrake Linux Security Advisory : htdig (MDKSA-2005:063)");
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
"A cross-site scripting vulnerability in ht://dig was discovered by
Michael Krax. The updated packages have been patched to correct this
issue."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected htdig, htdig-devel and / or htdig-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:htdig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:htdig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:htdig-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/01");
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
if (rpm_check(release:"MDK10.0", reference:"htdig-3.2.0-0.8.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"htdig-devel-3.2.0-0.8.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"htdig-web-3.2.0-0.8.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"htdig-3.2.0-0.8.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"htdig-devel-3.2.0-0.8.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"htdig-web-3.2.0-0.8.1.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
