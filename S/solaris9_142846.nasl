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
  script_id(71827);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 9 (sparc) : 142846-04");
  script_summary(english:"Check for patch 142846-04");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 142846-04"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Message Queue 4.4 Update 2 Patch 1 SunOS 5.9 5.10 Core product.
Date this patch was last updated by Sun : Nov/19/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/142846-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"142846-04", obsoleted_by:"", package:"SUNWiqfs", version:"4.4,REV=2009.08.27.08.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"142846-04", obsoleted_by:"", package:"SUNWiqum", version:"4.4,REV=2009.08.27.08.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"142846-04", obsoleted_by:"", package:"SUNWiqlen", version:"4.4,REV=2009.08.27.08.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"142846-04", obsoleted_by:"", package:"SUNWiqr", version:"4.4,REV=2009.08.27.08.32") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"142846-04", obsoleted_by:"", package:"SUNWiquc", version:"4.4,REV=2009.08.27.08.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"142846-04", obsoleted_by:"", package:"SUNWiqdoc", version:"4.4,REV=2009.08.27.08.32") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"142846-04", obsoleted_by:"", package:"SUNWiqu", version:"4.4,REV=2009.08.27.08.32") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"142846-04", obsoleted_by:"", package:"SUNWiqjx", version:"4.4,REV=2009.08.27.08.33") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
