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
  script_id(37630);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-6480");

  script_name(english:"Solaris 9 (sparc) : 127381-01");
  script_summary(english:"Check for patch 127381-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 127381-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Management Centre 3.6: Patch for Solaris 9.
Date this patch was last updated by Sun : Dec/11/07"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/127381-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/11");
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

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127381-01", obsoleted_by:"", package:"SUNWescom", version:"3.6,REV=2.9.2005.10.13") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
