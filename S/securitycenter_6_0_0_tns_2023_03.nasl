#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170729);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id(
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2023-0476",
    "CVE-2023-24493",
    "CVE-2023-24494",
    "CVE-2023-24495"
  );
  script_xref(name:"IAVA", value:"2023-A-0059");

  script_name(english:"Tenable SecurityCenter < 6.0.0 Multiple Vulnerabilities (TNS-2023-03)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
below 6.0.0 and is therefore affected by multiple vulnerabilities:
    
    - curl before 7.86.0 has a double free. If curl is told to use an HTTP proxy for a transfer with a 
      non-HTTP(S) URL, it sets up the connection to the remote server by issuing a CONNECT request to 
      the proxy, and then tunnels the rest of the protocol through. An HTTP proxy might refuse this 
      request (HTTP proxies often only allow outgoing connections to specific port numbers, like 443 
      for HTTPS) and instead return a non-200 status code to the client. Due to flaws in the error/cleanup 
      handling, this could trigger a double free in curl if one of the following schemes were used in the 
      URL for the transfer: dict, gopher, gophers, ldap, ldaps, rtmp, rtmps, or telnet. The earliest 
      affected version is 7.77.0.(CVE-2022-42915)

    - A LDAP injection vulnerability exists in Tenable.sc due to improper validation of user-supplied input 
      before returning it to users. An authenticated attacker could generate data in Active Directory using 
      the application account through blind LDAP injection. (CVE-2023-0476)

    - A formula injection vulnerability exists in Tenable.sc due to improper validation of user-supplied input 
      before returning it to users. An authenticated attacker could leverage the reporting system to export 
      reports containing formulas, which would then require a victim to approve and execute on a host. 
      (CVE-2023-24493)
    
    - A stored cross-site scripting (XSS) vulnerability exists in Tenable.sc due to improper validation of 
      user-supplied input before returning it to users. An authenticated, remote attacker can exploit this by 
      convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser 
      session. (CVE-2023-24494)

    - A Server Side Request Forgery (SSRF) vulnerability exists in Tenable.sc due to improper validation of 
      session & user-accessible input data. A privileged, authenticated remote attacker could interact with 
      external and internal services covertly. (CVE-2023-24495)

    - In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its 
      HSTS support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext HTTP 
      step) even when HTTP is provided in the URL. This mechanism could be bypassed if the host name in the 
      given URL uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion, 
      e.g., using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop of 
      U+002E (.). The earliest affected version is 7.77.0 2021-05-26. (CVE-2022-42916)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-03");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2023.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19633f44");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/27");

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

var app_info = vcf::tenable_sc::get_app_info();

var constraints = [
  { 'min_version' : '5.18.0', 'fixed_version': '6.0.0', 'fixed_display' : 'Upgrade to 6.0.0 or later'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{'xss':TRUE});