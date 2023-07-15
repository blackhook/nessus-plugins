#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104462);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12276");
  script_bugtraq_id(101640);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf47935");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-cpcp");

  script_name(english:"Cisco Prime Collaboration Provisioning < 12.3 Authenticated SQL Injection Vulnerability (cisco-sa-20171101-cpcp)");
  script_summary(english:"Checks the Cisco Prime Collaboration Provisioning version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management server is affected by a SQL injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Prime
Collaboration Provisioning server is 9.x, 10.x, 11.x, or 12.x prior to
12.3. It is, therefore, affected by an authenticated SQL injection
vulnerability.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-cpcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17d6b14c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Provisioning version 12.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12276");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Prime Collaboration Provisioning";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationProvisioning/version");

# We got the version from the WebUI and its not granular enough
if (version =~ "^(9|1[0-2])$")
  audit(AUDIT_VER_NOT_GRANULAR, appname, version);

fix = "12.3.0";

# 9.x - 12.x
if(version =~ "^(9|1[0-2])\." &&
  ver_compare(ver:version, fix:fix, strict:FALSE) < 0
)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING, sqli:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);

