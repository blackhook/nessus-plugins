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
  script_id(27039);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2007-3715",
    "CVE-2007-4164",
    "CVE-2008-2166",
    "CVE-2008-2518",
    "CVE-2009-3555"
  );
  script_xref(name:"IAVB", value:"2008-B-0045-S");

  script_name(english:"Solaris 9 (x86) : 125438-22");
  script_summary(english:"Check for patch 125438-22");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 125438-22"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Oracle iPlanet Web Server 7.0.12 Solaris_x86: Update Release patch.
Date this patch was last updated by Sun : Aug/26/11"
  );
  script_set_attribute(attribute:"see_also", value:"https://getupdates.oracle.com/readme/125438-22");
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125438-22", obsoleted_by:"", package:"SUNWwbsvr7-cli", version:"7.0,REV=2006.12.04.08.22") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125438-22", obsoleted_by:"", package:"SUNWwbsvr7", version:"7.0,REV=2006.12.04.08.22") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125438-22", obsoleted_by:"", package:"SUNWwbsvr7-dev", version:"7.0,REV=2006.12.04.08.22") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125438-22", obsoleted_by:"", package:"SUNWwbsvr7x", version:"7.0,REV=2006.12.04.09.01") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
