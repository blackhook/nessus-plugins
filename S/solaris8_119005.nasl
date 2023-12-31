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
  script_id(36716);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-2715");

  script_name(english:"Solaris 8 (sparc) : 119005-02");
  script_summary(english:"Check for patch 119005-02");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing Sun Security Patch number 119005-02");
  script_set_attribute(attribute:"description", value:
"NetBackup 4.5FP6 files fix. Date this patch was last updated by Sun :
Apr/14/06");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocContentDisplay?id=1682359.1");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/theme.jsp?themeid=sun-support");
  script_set_attribute(attribute:"solution", value:"You should install this patch for your system to be up-to-date.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

vendornote = '\nThis patch is no longer available from Oracle, as the Symantec Veritas\n' +
'NetBackup support contract with Oracle has ended. The patch has been\n' +
'removed from Oracle repositories.\n\n' +
'Please contact the vendor for product support :\n' +
'http://www.symantec.com/theme.jsp?themeid=sun-support';

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"119005-02", obsoleted_by:"", package:"VRTSnetbp", version:"4.5FP,REV=2003.11.03.15.48") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report() + vendornote);
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
