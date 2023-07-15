#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88592);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2016-1296");
  script_bugtraq_id(81434);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw32090");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux00848");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160119-wsa");

  script_name(english:"Cisco Web Security Appliance Proxy Restrictions Bypass");
  script_summary(english:"Checks the WSA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Web Security
Appliance (WSA) running on the remote host is affected by a security
feature bypass vulnerability that allows an unauthenticated, remote
attacker to bypass proxy restrictions via improper or malformed HTTP
methods.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160119-wsa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?689662ba");
  script_set_attribute(attribute:"solution", value:
"No patch currently exists. Contact Cisco for a patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1296");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Settings/ParanoidReport", "Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/Version');

# Device might not even be configured to prevent proxied traffic
# and Cisco doesn't seem like they want to patch this anytime soon
if (report_paranoia < 2) audit(AUDIT_PARANOID);

display_fix = FALSE;
if (ver == "8.5.3.055")
  display_fix = 'No fix has been supplied by Cisco.';
else if (ver == "9.1.0.000")
  display_fix = 'No fix has been supplied by Cisco.';
else if (ver == "9.5.0.235")
  display_fix = 'No fix has been supplied by Cisco.';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);

if (display_fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Solution          : ' + display_fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);
