#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156557);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id("CVE-2021-44224", "CVE-2021-44790", "CVE-2022-0130");

  script_name(english:"Tenable SecurityCenter < 5.20.0 Multiple Vulnerabilities (TNS-2022-01)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is less 
than 5.20.0 and is therefore affected by multiple vulnerabilities:

- A crafted URI sent to httpd configured as a forward proxy (ProxyRequests on) can cause a crash (NULL pointer 
  dereference) or, for configurations mixing forward and reverse proxy declarations, can allow for requests to be 
  directed to a declared Unix Domain Socket endpoint (Server Side Request Forgery). This issue affects Apache HTTP 
  Server 2.4.7 up to 2.4.51 (included). (CVE-2021-44224)

- A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called 
  from Lua scripts). The Apache httpd team is not aware of an exploit for the vulnerability though it might be possible 
  to craft one. This issue affects Apache HTTP Server 2.4.51 and earlier. (CVE-2021-44790)
  
Note that successful exploitation of the most serious issues can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-01");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory or upgrade to 5.20.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44790");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202201.1');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'min_version' : '5.14.0', 'max_version': '5.15', 'fixed_display' : 'Upgrade to 5.20.0 or later'},
  { 'min_version' : '5.16.0', 'max_version' : '5.19.1', 'fixed_display' : 'Apply Patch SC-202201.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
