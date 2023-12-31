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
  script_id(13548);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-4339", "CVE-2006-5201", "CVE-2006-7140");

  script_name(english:"Solaris 9 (sparc) : 114049-14");
  script_summary(english:"Check for patch 114049-14");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 114049-14"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9: NSPR 4.1.6 / NSS 3.3.4.8.
Date this patch was last updated by Sun : Nov/07/06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.oracle.com/sunalerts/1000472.1.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/07");
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

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114049-14", obsoleted_by:"", package:"SUNWtls", version:"3.3.2,REV=2002.09.18.12.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114049-14", obsoleted_by:"", package:"SUNWprx", version:"4.1.2,REV=2002.09.03.00.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114049-14", obsoleted_by:"", package:"SUNWpr", version:"4.1.2,REV=2002.09.03.00.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114049-14", obsoleted_by:"", package:"SUNWtlsx", version:"3.3.2,REV=2002.09.18.12.49") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
