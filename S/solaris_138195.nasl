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
  script_id(44397);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris Unbundled (sparc) : 138195-04");
  script_summary(english:"Check for patch 138195-04");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 138195-04"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Service Tags 1.0: patch for Solaris 10.
Date this patch was last updated by Sun : Mar/19/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/138195-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"10", arch:"sparc", patch:"138195-04", obsoleted_by:"", package:"SUNWservicetagu", version:"1.0,REV=2007.05.21.20.36") < 0) flag++;
if (solaris_check_patch(release:"10", arch:"sparc", patch:"138195-04", obsoleted_by:"", package:"SUNWservicetagr", version:"1.0,REV=2007.05.21.20.36") < 0) flag++;
if (solaris_check_patch(release:"10", arch:"sparc", patch:"138195-04", obsoleted_by:"", package:"SUNWstosreg", version:"1.0,REV=2007.05.21.20.36") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
