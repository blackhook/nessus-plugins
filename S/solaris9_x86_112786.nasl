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
  script_id(14366);
  script_version("1.44");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-5684");

  script_name(english:"Solaris 9 (x86) : 112786-54");
  script_summary(english:"Check for patch 112786-54");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 112786-54"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"X11 6.6.1_x86: Xsun patch.
Date this patch was last updated by Sun : Dec/11/08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.oracle.com/sunalerts/1019677.1.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/24");
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

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwinc", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwsrv", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwfnt", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwpmn", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwslb", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwplt", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwice", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwopt", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwacx", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-54", obsoleted_by:"", package:"SUNWxwman", version:"6.6.1.6400,REV=0.2002.10.16") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
