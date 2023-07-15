##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144584);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-1551",
    "CVE-2020-1967",
    "CVE-2020-1971",
    "CVE-2020-5808",
    "CVE-2020-11022"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Tenable SecurityCenter < 5.17.0 Multiple Vulnerabilities (TNS-2020-11)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter
application installed on the remote host is earlier than 5.17.0. It is,
therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues nor the stand-alone
patch but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2020-11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.17.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5808");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

port = get_http_port(default:443, dont_exit:TRUE);
app_info = vcf::tenable_sc::get_app_info(port:port);

constraints = [
  {'fixed_version':'5.16.1', 'fixed_display':'5.17.0'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
