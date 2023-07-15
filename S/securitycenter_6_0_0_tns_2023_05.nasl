##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(171869);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2022-42915", "CVE-2022-42916");
  script_xref(name:"IAVA", value:"2023-A-0059");

  script_name(english:"Tenable SecurityCenter 5.22.0 / 5.23.1 Multiple Vulnerabilities (TNS-2023-05)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
running 5.22.0 or 5.23.1 and is therefore affected by multiple vulnerabilities in curl starting with 7.77.0 and 
before 7.86.0:
    
    - If curl is told to use an HTTP proxy for a transfer with a non-HTTP(S) URL, it sets up the connection
      to the remote server by issuing a CONNECT request to the proxy, and then tunnels the rest of the protocol 
      through. An HTTP proxy might refuse this request (HTTP proxies often only allow outgoing connections to 
      specific port numbers, like 443 for HTTPS) and instead return a non-200 status code to the client. Due to 
      flaws in the error/cleanup handling, this could trigger a double free in curl if one of the following schemes 
      were used in the URL for the transfer: dict, gopher, gophers, ldap, ldaps, rtmp, rtmps, or telnet. (CVE-2022-42915)
    
    - In curl the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS support, curl can be 
      instructed to use HTTPS directly (instead of using an insecure cleartext HTTP step) even when HTTP is provided 
      in the URL. This mechanism could be bypassed if the host name in the given URL uses IDN characters that get 
      replaced with ASCII counterparts as part of the IDN conversion. (CVE-2022-42916)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-05");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2023.htm#2023023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c126983d");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202302.3');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
    { 'min_version' : '5.22.0', 'max_version': '5.23.1', 'fixed_display' : 'Apply Patch SC-202302.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
