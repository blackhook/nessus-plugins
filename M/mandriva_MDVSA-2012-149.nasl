#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:149. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61992);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2011-3389", "CVE-2012-3482");
  script_bugtraq_id(49778, 54987);
  script_xref(name:"MDVSA", value:"2012:149");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Mandriva Linux Security Advisory : fetchmail (MDVSA-2012:149)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mandriva Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities has been found and corrected in fetchmail :

Fetchmail version 6.3.9 enabled all SSL workarounds (SSL_OP_ALL) which
contains a switch to disable a countermeasure against certain attacks
against block ciphers that permit guessing the initialization vectors,
providing that an attacker can make the application (fetchmail)
encrypt some data for him -- which is not easily the case (aka a BEAST
attack) (CVE-2011-3389).

A denial of service flaw was found in the way Fetchmail, a remote mail
retrieval and forwarding utility, performed base64 decoding of certain
NTLM server responses. Upon sending the NTLM authentication request,
Fetchmail did not check if the received response was actually part of
NTLM protocol exchange, or server-side error message and session
abort. A rogue NTML server could use this flaw to cause fetchmail
executable crash (CVE-2012-3482).

This advisory provides the latest version of fetchmail (6.3.22) which
is not vulnerable to these issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.fetchmail.info/fetchmail-SA-2012-01.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.fetchmail.info/fetchmail-SA-2012-02.txt");
  script_set_attribute(attribute:"solution", value:
"Update the affected fetchmail, fetchmail-daemon and / or fetchmailconf
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fetchmail-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fetchmailconf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"MDK2011", reference:"fetchmail-6.3.22-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"fetchmail-daemon-6.3.22-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"fetchmailconf-6.3.22-0.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
