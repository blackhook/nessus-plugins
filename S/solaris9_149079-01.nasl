#%NASL_MIN_LEVEL 70300
# @DEPRECATED@
#
# This script has been deprecated by solaris9_149079.nasl.
#
# Disabled on 2014/10/13.
#

#
# (C) Tenable Network Security, Inc.
#

#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77911);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103, 70137);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"Solaris 9 (sparc) : 149079-01");
  script_summary(english:"Check for patch 149079-01");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing Oracle Security Patch number 149079-01");
  script_set_attribute(attribute:"description", value:
"SunOS 5.9: bash patch. 

Date this patch was last updated by Oracle : Sep/26/14");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/2014/09/cve-2014-6271/");
  script_set_attribute(attribute:"see_also", value:"https://blogs.oracle.com/patch/entry/solaris_idrs_available_on_mos");
  script_set_attribute(attribute:"see_also", value:"https://getupdates.oracle.com/readme/149079-01");
  script_set_attribute(attribute:"solution", value:"You should install this patch for your system to be up-to-date.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pure-FTPd External Authentication Bash Environment Variable Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev", "Host/Solaris/pkginfo");

  exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #78112 (solaris9_149079.nasl) instead.");

include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Solaris/showrev")) audit(AUDIT_OS_NOT, "Solaris 10 or earlier");
if (!get_kb_item("Host/Solaris/pkginfo")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"149079-01", obsoleted_by:"", package:"SUNWbash", version:"11.9.0,REV=2002.03.02.00.35") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"149079-01", obsoleted_by:"", package:"SUNWbashS", version:"11.9.0,REV=2002.03.02.00.35") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
