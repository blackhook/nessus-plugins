#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated as the associated update is not
# for a supported release of Mandrake / Mandriva Linux.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandrake Linux Security Advisory MDKSA-2005:172.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(20426);
  script_version ("1.11");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_cve_id("CVE-2005-2798");

  script_name(english:"MDKSA-2005:172 : openssh");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Sshd in OpenSSH before 4.2, when GSSAPIDelegateCredentials is
enabled, allows GSSAPI credentials to be delegated to clients who log
in using non-GSSAPI methods, which could cause those credentials to
be exposed to untrusted users or hosts.

GSSAPI is only enabled in versions of openssh shipped in LE2005 and
greater.

The updated packages have been patched to correct this issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKSA-2005:172");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/06");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/15");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2006-2018 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated update is not currently for a supported release of Mandrake / Mandriva Linux.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"openssh-3.9p1-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"openssh-askpass-3.9p1-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"openssh-askpass-gnome-3.9p1-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"openssh-clients-3.9p1-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"openssh-server-3.9p1-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else 
{
  if (rpm_exists(rpm:"openssh-", release:"MDK10.2"))
  {
    set_kb_item(name:"CVE-2005-2798", value:TRUE);
  }

  exit(0, "The host is not affected.");
}
