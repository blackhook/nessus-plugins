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
  script_id(23238);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 7 (sparc) : 110937-22");
  script_summary(english:"Check for patch 110937-22");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 110937-22"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Management Center 3.0: (GA) Patch for Solaris 7.
Date this patch was last updated by Sun : Apr/07/05"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/110937-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/07");
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

if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesjp", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesdb", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesmsg", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWessts", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWedagx", version:"1.1,REV=41.2000.12.14,OE=S7") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesweb", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesasc", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWeswgs", version:"3.0_Build40,REV=2.7.2000.12.08") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWessta", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWedcom", version:"1.1,REV=41.2000.12.14,OE=S2.6") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWescaa", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWessvc", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWessmn", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesmcp", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWmeta", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWessrv", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWescix", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWedag", version:"1.1,REV=41.2000.12.14,OE=S7") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWessdk", version:"3.0,REV=2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWescon", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWescam", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesamn", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesagt", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesae", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWeswga", version:"3.0_Build40,REV=2.7.2000.12.08") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWescom", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWessa", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesora", version:"3.0,REV=2000.10.27") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesjrm", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWescli", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesmod", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWsycfd", version:"3.0_Build41,REV=2.7.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWesclt", version:"3.0_Build41,REV=2.6.2000.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.7", arch:"sparc", patch:"110937-22", obsoleted_by:"", package:"SUNWed", version:"1.1,REV=41.2000.12.14,OE=S2.6") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
