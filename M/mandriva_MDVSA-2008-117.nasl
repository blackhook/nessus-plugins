#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:117. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36958);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2008-2711");
  script_bugtraq_id(29705);
  script_xref(name:"MDVSA", value:"2008:117");

  script_name(english:"Mandriva Linux Security Advisory : fetchmail (MDVSA-2008:117)");
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
"A flaw in fetchmail was discovered that allowed remote attackers to
cause a denial of service (crash and persistent mail failure) via a
malformed message with long headers. The crash only occured when
fetchmail was called in '-v -v' mode (CVE-2008-2711).

The updated packages have been patched to prevent this issue."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected fetchmail, fetchmail-daemon and / or fetchmailconf
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fetchmail-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fetchmailconf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"MDK2007.1", reference:"fetchmail-6.3.6-1.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"fetchmail-daemon-6.3.6-1.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"fetchmailconf-6.3.6-1.3mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"fetchmail-6.3.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"fetchmail-daemon-6.3.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"fetchmailconf-6.3.8-4.1mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"fetchmail-6.3.8-7.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"fetchmail-daemon-6.3.8-7.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"fetchmailconf-6.3.8-7.1mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
