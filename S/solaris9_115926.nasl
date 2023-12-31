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
  script_id(13568);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 9 (sparc) : 115926-10");
  script_summary(english:"Check for patch 115926-10");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 115926-10"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9: NSPR 4.1.6 / NSS 3.3.11 / JSS 3.
Date this patch was last updated by Sun : Aug/09/04"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/115926-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115926-10", obsoleted_by:"117724-10 119211-05 ", package:"SUNWtls", version:"3.3.2,REV=2002.09.18.12.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115926-10", obsoleted_by:"117724-10 119211-05 ", package:"SUNWprx", version:"4.1.2,REV=2002.09.03.00.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115926-10", obsoleted_by:"117724-10 119211-05 ", package:"SUNWpr", version:"4.1.2,REV=2002.09.03.00.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115926-10", obsoleted_by:"117724-10 119211-05 ", package:"SUNWtlsu", version:"3.3.7,REV=2003.12.01.12.23") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115926-10", obsoleted_by:"117724-10 119211-05 ", package:"SUNWjss", version:"3.1.2.3,REV=2003.03.08.12.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115926-10", obsoleted_by:"117724-10 119211-05 ", package:"SUNWtlsux", version:"3.3.10,REV=2004.03.25.01.10") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115926-10", obsoleted_by:"117724-10 119211-05 ", package:"SUNWtlsx", version:"3.3.2,REV=2002.09.18.12.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115926-10", obsoleted_by:"117724-10 119211-05 ", package:"SUNWjssx", version:"3.1.2.3,REV=2003.03.08.12.22") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
