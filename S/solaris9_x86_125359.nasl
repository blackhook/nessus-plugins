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
  script_id(24863);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 9 (x86) : 125359-25");
  script_summary(english:"Check for patch 125359-25");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 125359-25"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NSS_NSPR_JSS 3.30.2 Solaris_x86: NSPR 4.15 / NSS 3.30.2 / JSS 4.3..
Date this patch was last updated by Sun : Nov/11/17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/125359-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125359-25", obsoleted_by:"", package:"SUNWtls", version:"3.11.4,REV=2006.11.16.21.41") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125359-25", obsoleted_by:"", package:"SUNWtlsd", version:"3.11.4,REV=2006.11.16.21.41") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125359-25", obsoleted_by:"", package:"SUNWprd", version:"4.6.4,REV=2006.11.16.21.41") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125359-25", obsoleted_by:"", package:"SUNWjss", version:"4.2.4,REV=2006.11.16.21.41") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125359-25", obsoleted_by:"", package:"SUNWpr", version:"4.6.4,REV=2006.11.16.21.41") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125359-25", obsoleted_by:"", package:"SUNWtlsu", version:"3.11.4,REV=2006.11.16.21.41") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
