#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175782);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id("CVE-2023-29240");
  script_xref(name:"IAVA", value:"2023-A-0237");

  script_name(english:"F5 Networks BIG-IQ iControl REST Arbitrary File Upload (K000132719)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IQ Centralized Management installed on the remote host is affected
by an arbitrary file upload vulnerability as referenced in the K000132719 advisory. An authenticated 
attacker granted a Viewer or Auditor role on a BIG-IQ system can upload arbitrary files using an 
undisclosed iControl REST endpoint. (CVE-2023-29240)");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000132719");
  script_set_attribute(attribute:"solution", value:
"Upgrade to F5 Networks BIG-IQ version 8.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29240");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-iq");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-iq_centralized_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigiq_detect.nbin");
  script_require_keys("Host/BIG-IQ/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

var version = get_kb_item_or_exit("Host/BIG-IQ/version");
var hotfix  = get_kb_item_or_exit("Host/BIG-IQ/hotfix");

# Even if LDAP is configured, the LDAP server 
# has to also allow anonymous binds, there is 
# no way to check for this. 
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var fix = FALSE;
if (version =~ "^8\.[0-2](\.|$)")
  fix = "8.3.0";
else
  audit(AUDIT_INST_VER_NOT_VULN, "BIG-IQ", version);

if (fix)
{
  if (report_verbosity > 0)
  {
    var  report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "BIG-IQ", version);
