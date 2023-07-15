#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110535);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2018-0353");
  script_bugtraq_id(104417);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg78875");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180606-wsa");

  script_name(english:"Cisco Web Security Appliance L4 Traffic Monitor Bypass");
  script_summary(english:"Checks the WSA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Web Security
Appliance (WSA) running on the remote host is affected by a security
feature bypass vulnerability that allows an unauthenticated, remote
attacker to bypass L4 Traffic Monitor (L4TM) restrictions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-wsa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0730b76");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg78875
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea9b4f43");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Settings/ParanoidReport", "Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion');
# In 'ver', '-' is already converted to '.' by detection
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/Version');

# Device might not even be configured for L4TM
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Granularity check
if (
  ver == "10" || ver == "10.5" || ver == "10.5.2" ||
  ver == "11" || ver == "11.5" || ver == "11.5.0"
) audit(AUDIT_VER_NOT_GRANULAR, 'Cisco Web Security Appliance', ver);

display_fix = FALSE;

# 10.5.1.x / 10.5.2.x < 10.5.2.042
if (
  ver =~ "^10\.5\.1($|[^0-9])" ||
  ver =~ "^10\.5\.2\.0?([0-9]|[1-3][0-9]|4[01])($|[^0-9])"
)
{
  display_fix = "10.5.2-042";
}
# 11.0.x - 11.5.x < 11.5.0.0614
else if (
  ver =~ "^11\.[01234]($|[^0-9])" ||
  ver =~ "^11\.5\.0\.0?([0-9]|[0-9][0-9]|[1-5][0-9][0-9])($|[^0-9])" ||
  ver =~ "^11\.5\.0\.0?6(0[0-9]|1[0-3])($|[^0-9])" ||
  ver == "11.5.0.FCS.442" # specifically listed in Cisco Bug
)
{
  display_fix = "11.5.0-0614";
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);

if (display_fix)
{
  report =
    '\n  Installed version : ' + display_ver +
    '\n  Solution          : ' + display_fix +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);
