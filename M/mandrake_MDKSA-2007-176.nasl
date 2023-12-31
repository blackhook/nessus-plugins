#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:176. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26008);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-3820", "CVE-2007-4224", "CVE-2007-4225");
  script_bugtraq_id(24912);
  script_xref(name:"MDKSA", value:"2007:176");

  script_name(english:"Mandrake Linux Security Advisory : konqueror (MDKSA-2007:176)");
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
"konqueror/konq_combo.cc in Konqueror 3.5.7 allows remote attackers to
spoof the data: URI scheme in the address bar via a long URI with
trailing whitespace, which prevents the beginning of the URI from
being displayed. (CVE-2007-3820)

KDE Konqueror 3.5.7 allows remote attackers to spoof the URL address
bar by calling setInterval with a small interval and changing the
window.location property. (CVE-2007-4224)

Visual truncation vulnerability in KDE Konqueror 3.5.7 allows remote
attackers to spoof the URL address bar via an http URI with a large
amount of whitespace in the user/password portion. (CVE-2007-4225)

Updated packages fix these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdeprintfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-session-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kate-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kate-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"MDK2007.0", reference:"kdebase-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdebase-common-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdebase-kate-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdebase-kdeprintfax-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdebase-kdm-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdebase-kmenuedit-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdebase-konsole-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdebase-nsplugins-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdebase-progs-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdelibs-common-3.5.4-19.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdelibs-devel-doc-3.5.4-19.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdebase4-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdebase4-devel-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdebase4-kate-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdebase4-kate-devel-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdebase4-kmenuedit-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdebase4-konsole-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdecore4-3.5.4-19.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdecore4-devel-3.5.4-19.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdebase4-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdebase4-devel-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdebase4-kate-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdebase4-kate-devel-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdebase4-kmenuedit-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdebase4-konsole-3.5.4-35.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdecore4-3.5.4-19.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdecore4-devel-3.5.4-19.6mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"kdebase-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdebase-common-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdebase-kate-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdebase-kdeprintfax-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdebase-kdm-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdebase-kmenuedit-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdebase-konsole-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdebase-nsplugins-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdebase-progs-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdebase-session-plugins-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdelibs-common-3.5.6-11.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kdelibs-devel-doc-3.5.6-11.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64kdebase4-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64kdebase4-devel-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64kdebase4-kate-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64kdebase4-kate-devel-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64kdebase4-kmenuedit-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64kdebase4-konsole-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64kdecore4-3.5.6-11.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64kdecore4-devel-3.5.6-11.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkdebase4-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkdebase4-devel-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkdebase4-kate-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkdebase4-kate-devel-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkdebase4-kmenuedit-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkdebase4-konsole-3.5.6-34.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkdecore4-3.5.6-11.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkdecore4-devel-3.5.6-11.2mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
