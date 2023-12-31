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
  script_id(23550);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-5423");

  script_name(english:"Solaris 9 (sparc) : 118979-04");
  script_summary(english:"Check for patch 118979-04");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 118979-04"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Ray Core Services version 3.0 Patch Update.
Date this patch was last updated by Sun : Nov/26/08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/118979-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/26");
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

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"118979-04", obsoleted_by:"", package:"SUNWutstk", version:"3.0_51,REV=2004.11.10.16.18") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"118979-04", obsoleted_by:"", package:"SUNWutu", version:"3.0_51,REV=2004.11.10.16.18") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"118979-04", obsoleted_by:"", package:"SUNWutfw", version:"3.0_51,REV=2004.11.10.16.18") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"118979-04", obsoleted_by:"", package:"SUNWuto", version:"3.0_51,REV=2004.11.10.16.18") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"118979-04", obsoleted_by:"", package:"SUNWutesa", version:"3.0_51,REV=2004.11.10.16.18") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"118979-04", obsoleted_by:"", package:"SUNWutsto", version:"3.0_51,REV=2004.11.10.16.18") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"118979-04", obsoleted_by:"", package:"SUNWutps", version:"3.0_51,REV=2004.11.10.16.18") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"118979-04", obsoleted_by:"", package:"SUNWuta", version:"3.0_51,REV=2004.11.10.16.18") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"118979-04", obsoleted_by:"", package:"SUNWutr", version:"3.0_51,REV=2004.11.10.16.18") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
