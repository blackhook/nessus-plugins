#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:125. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76068);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-1545");
  script_bugtraq_id(67975);
  script_xref(name:"MDVSA", value:"2014:125");

  script_name(english:"Mandriva Linux Security Advisory : nspr (MDVSA-2014:125)");
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
"A vulnerability has been discovered and corrected in nspr :

Mozilla Netscape Portable Runtime (NSPR) before 4.10.6 allows remote
attackers to execute arbitrary code or cause a denial of service
(out-of-bounds write) via vectors involving the sprintf and console
functions (CVE-2014-1545).

The updated nspr packages have been upgraded to the 4.10.6 version
which is unaffected by this issue.

Additionally :

  - The rootcerts package have been upgraded to the latest
    version as of 2014-04-01.

  - The nss packages have been upgraded to the latest 3.16.1
    version which resolves various bugs.

  - The sqlite3 packages have been upgraded to the 3.7.17
    version for mbs1 due to an prerequisite to nss-3.16.1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-55/"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.16.1_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b157b539"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sqlite3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sqlite3-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sqlite3_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sqlite3-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sqlite3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lemon-3.7.17-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nspr-devel-4.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nspr4-4.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nss-devel-3.16.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nss-static-devel-3.16.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nss3-3.16.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64sqlite3-devel-3.7.17-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64sqlite3-static-devel-3.7.17-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64sqlite3_0-3.7.17-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nss-3.16.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"nss-doc-3.16.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rootcerts-20140401.00-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rootcerts-java-20140401.00-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"sqlite3-tcl-3.7.17-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"sqlite3-tools-3.7.17-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
