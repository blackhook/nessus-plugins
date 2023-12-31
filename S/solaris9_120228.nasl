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
  script_id(25398);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-2904", "CVE-2011-0411");

  script_name(english:"Solaris 9 (sparc) : 120228-45");
  script_summary(english:"Check for patch 120228-45");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 120228-45"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Messaging Server 6.3-16.01: core patch.
Date this patch was last updated by Sun : Nov/30/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/120228-45"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/04");
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

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"120228-45", obsoleted_by:"", package:"SUNWmsgco", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"120228-45", obsoleted_by:"", package:"SUNWmsgmp", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"120228-45", obsoleted_by:"", package:"SUNWmsglb", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"120228-45", obsoleted_by:"", package:"SUNWmsgwm", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"120228-45", obsoleted_by:"", package:"SUNWmsgmt", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"120228-45", obsoleted_by:"", package:"SUNWmsgin", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"120228-45", obsoleted_by:"", package:"SUNWmsgen", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"120228-45", obsoleted_by:"", package:"SUNWmsgst", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"120228-45", obsoleted_by:"", package:"SUNWmsgmf", version:"6.0,REV=2003.10.29") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
