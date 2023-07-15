#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176378);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id(
    "CVE-2021-27855",
    "CVE-2021-27856",
    "CVE-2021-27857",
    "CVE-2021-27858",
    "CVE-2021-27859"
  );

  script_name(english:"FatPipe MPVPN < 10.1.2r60p91 / 10.2.2 < 10.2.2r42 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of FatPipe MPVPN running on the remote web server is <
10.1.2r60p91 or 10.2.2 < 10.2.2r42. It is, therefore, affected by multiple vulnerabilities, including:

    - FatPipe WARP, IPVPN, and MPVPN software prior to versions 10.1.2r60p91 and 10.2.2r42 includes an account named
      'cmuser' that has administrative privileges and no password. (CVE-2021-27856)

    - FatPipe WARP, IPVPN, and MPVPN software prior to versions 10.1.2r60p91 and 10.2.2r42 allows a remote,
      authenticated attacker with read-only privileges to grant themselves administrative privileges. (CVE-2021-27855)

    - A missing authorization vulnerability in the web management interface of FatPipe WARP, IPVPN, and MPVPN software
      prior to versions 10.1.2r60p91 and 10.2.2r42 allows an authenticated, remote attacker with read-only privileges to
      create an account with administrative privileges. (CVE-2021-27859)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fatpipeinc.com/fpsa/fpsa001.php");
  script_set_attribute(attribute:"see_also", value:"https://www.fatpipeinc.com/fpsa/fpsa002.php");
  script_set_attribute(attribute:"see_also", value:"https://www.fatpipeinc.com/fpsa/fpsa003.php");
  script_set_attribute(attribute:"see_also", value:"https://www.fatpipeinc.com/fpsa/fpsa004.php");
  script_set_attribute(attribute:"see_also", value:"https://www.fatpipeinc.com/fpsa/fpsa005.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FatPipe MPVPN 10.1.2r60p91 or 10.2.2r42 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27856");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fatpipeinc:mpvpn_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fatpipe_mpvpn_web_detect.nbin");
  script_require_keys("installed_sw/FatPipe MPVPN");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'FatPipe MPVPN', port:port, webapp:TRUE);

var constraints = [
  {'fixed_version':'10.1.2.60.91', 'fixed_display':'10.1.2r60p91'},
  {'min_version':'10.2.2', 'fixed_version':'10.2.2.42', 'fixed_display':'10.2.2r42'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);