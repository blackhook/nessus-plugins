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
  script_id(13419);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-2430");

  script_name(english:"Solaris 8 (x86) : 109008-28");
  script_summary(english:"Check for patch 109008-28");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 109008-28"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.8_x86: at/atrm/batch/cron/inetd pa.
Date this patch was last updated by Sun : Mar/26/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.oracle.com/sunalerts/1020636.1.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/26");
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

if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109008-28", obsoleted_by:"", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109008-28", obsoleted_by:"", package:"SUNWcstl", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109008-28", obsoleted_by:"", package:"SUNWesu", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109008-28", obsoleted_by:"", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109008-28", obsoleted_by:"", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109008-28", obsoleted_by:"", package:"SUNWcsl", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109008-28", obsoleted_by:"", package:"SUNWarc", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
