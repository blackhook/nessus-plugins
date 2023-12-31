#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56688);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0411");

  script_name(english:"Solaris 9 (sparc) : 115336-06");
  script_summary(english:"Check for patch 115336-06");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 115336-06"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: RBAC Configuration). Supported versions
that are affected are 8, 9 and 10. Very difficult to exploit
vulnerability requiring logon to Operating System plus additional,
multiple logins to components. Successful attack of this vulnerability
can escalate attacker privileges resulting in unauthorized Operating
System takeover including arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/115336-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115336-06", obsoleted_by:"", package:"SUNWsutl", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115336-06", obsoleted_by:"", package:"SUNWcsu", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115336-06", obsoleted_by:"", package:"SUNWcsr", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
