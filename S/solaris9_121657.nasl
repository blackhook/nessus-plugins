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
  script_id(33213);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-1218", "CVE-2009-1219");

  script_name(english:"Solaris 9 (sparc) : 121657-54");
  script_summary(english:"Check for patch 121657-54");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 121657-54"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Calendar Server SunOS 5.9 5.10: Core patch.
Date this patch was last updated by Sun : Aug/14/13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/121657-54"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWica5", version:"6.0,REV=2003.11.14.18.12.58") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWics5", version:"6.0,REV=2003.11.14.18.12.58") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWfrics", version:"6.0,REV=2003.11.14.15.16.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWkoics", version:"6.0,REV=2003.11.14.15.16.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWzhics", version:"6.0,REV=2003.11.14.15.16.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWics-l10n", version:"6.3,REV=2007.01.05.03.20.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWjaics", version:"6.0,REV=2003.11.14.15.16.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWdeics", version:"6.0,REV=2003.11.14.15.16.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWtwics", version:"6.0,REV=2003.11.14.15.16.33") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"121657-54", obsoleted_by:"", package:"SUNWesics", version:"6.0,REV=2003.11.14.15.16.33") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
