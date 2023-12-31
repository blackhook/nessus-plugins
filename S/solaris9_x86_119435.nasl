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
  script_id(22249);
  script_version("1.50");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2006-5073", "CVE-2007-2045", "CVE-2008-1095", "CVE-2008-1779", "CVE-2008-2121", "CVE-2009-0346", "CVE-2009-0480");
  script_bugtraq_id(29089);
  script_xref(name:"IAVT", value:"2008-T-0014-S");
  script_xref(name:"IAVT", value:"2008-T-0022-S");

  script_name(english:"Solaris 9 (x86) : 119435-29");
  script_summary(english:"Check for patch 119435-29");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119435-29"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9_x86: ip patch.
Date this patch was last updated by Sun : Mar/05/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119435-29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 189, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"119435-29", obsoleted_by:"122301-62 ", package:"SUNWcsu", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"119435-29", obsoleted_by:"122301-62 ", package:"SUNWhea", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"119435-29", obsoleted_by:"122301-62 ", package:"SUNWcstl", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"119435-29", obsoleted_by:"122301-62 ", package:"SUNWcsr", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"119435-29", obsoleted_by:"122301-62 ", package:"SUNWcsl", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"119435-29", obsoleted_by:"122301-62 ", package:"SUNWarc", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
