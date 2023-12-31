#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:190. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77950);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/31");

  script_cve_id("CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_bugtraq_id(70137);
  script_xref(name:"MDVSA", value:"2014:190");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");

  script_name(english:"Mandriva Linux Security Advisory : bash (MDVSA-2014:190)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mandriva Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"It was found that the fix for CVE-2014-6271 was incomplete, and Bash
still allowed certain characters to be injected into other
environments via specially crafted environment variables. An attacker
could potentially use this flaw to override or bypass environment
restrictions to execute shell commands. Certain services and
applications allow remote unauthenticated attackers to provide
environment variables, allowing them to exploit this issue
(CVE-2014-7169, CVE-2014-7186, CVE-2014-7187).

Additionally bash has been updated from patch level 37 to 48 using the
upstream patches at ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/ which
resolves various bugs.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1306");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1311");
  script_set_attribute(attribute:"solution", value:
"Update the affected bash and / or bash-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"bash-4.2-48.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"bash-doc-4.2-48.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
