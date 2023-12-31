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
  script_id(23364);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 8 (sparc) : 114795-05");
  script_summary(english:"Check for patch 114795-05");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 114795-05"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Crypto Accelerator 4000 - 1.0: product patch.
Date this patch was last updated by Sun : Feb/24/04"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/114795-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"114795-05", obsoleted_by:"", package:"SUNWkcl2r", version:"2.0.0,REV=2003.03.19.18.18") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"114795-05", obsoleted_by:"", package:"SUNWvcar", version:"1.0.0,REV=2003.03.19.18.25") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"114795-05", obsoleted_by:"", package:"SUNWvcafw", version:"1.0.0,REV=2003.03.19.18.46") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"114795-05", obsoleted_by:"", package:"SUNWvcau", version:"1.0.0,REV=2003.03.19.18.25") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"114795-05", obsoleted_by:"", package:"SUNWvcaa", version:"1.0.0,REV=2003.03.19.18.25") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"114795-05", obsoleted_by:"", package:"SUNWkcl2u", version:"2.0.0,REV=2003.03.19.18.18") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
