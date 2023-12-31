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
  script_id(90579);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 8 (x86) : 152098-53");
  script_summary(english:"Check for patch 152098-53");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 152098-53"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"JavaSE 7_x86: update 151 patch (equivalent to JDK 7u151).
Date this patch was last updated by Sun : Jul/17/17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/152098-53"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"152098-53", obsoleted_by:"", package:"SUNWj7man", version:"1.7.0,REV=2011.06.27.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"152098-53", obsoleted_by:"", package:"SUNWj7cfg", version:"1.7.0,REV=2011.06.27.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"152098-53", obsoleted_by:"", package:"SUNWj7dmo", version:"1.7.0,REV=2011.06.27.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"152098-53", obsoleted_by:"", package:"SUNWj7dev", version:"1.7.0,REV=2011.06.27.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"152098-53", obsoleted_by:"", package:"SUNWj7jmp", version:"1.7.0,REV=2011.06.27.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"152098-53", obsoleted_by:"", package:"SUNWj7rt", version:"1.7.0,REV=2011.06.27.03.37") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
