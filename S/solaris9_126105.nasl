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
  script_id(27024);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-2267", "CVE-2009-3433");
  script_bugtraq_id(36486);
  script_xref(name:"IAVA", value:"2009-A-0087-S");

  script_name(english:"Solaris 9 (sparc) : 126105-42");
  script_summary(english:"Check for patch 126105-42");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 126105-42"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Cluster 3.2: CORE patch for Solaris 9.
Date this patch was last updated by Sun : Apr/27/10"
  );
  script_set_attribute(attribute:"see_also", value:"https://getupdates.oracle.com/readme/126105-42");
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscrtlh", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscmd", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWsczu", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscdev", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscucm", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscsam", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscu", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscmasa", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWudlmr", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscmasar", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscmautil", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWcvm", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscsal", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscmasau", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWsctelemetry", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWccon", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscmasasen", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscr", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscspmu", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWcvmr", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWsccomzu", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscssv", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscderby", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscrif", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWsccomu", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWudlm", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-42", obsoleted_by:"", package:"SUNWscgds", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
