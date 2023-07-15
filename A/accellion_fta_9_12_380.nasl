#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154933);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-27101",
    "CVE-2021-27102",
    "CVE-2021-27103",
    "CVE-2021-27104"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0011");

  script_name(english:"Accellion File Transfer Appliance < 9_12_416 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote Accellion Secure File Transfer Appliance is prior to 9_12_416. It is, therefore, 
affected by multiple vulnerabilities:

 - SQL injection via a crafted Host header in a request to an endpoint. (CVE-2021-27101)

 - OS command execution via a local web service call. (CVE-2021-27102)

 - SSRF via a crafted POST request to an endpoint. (CVE-2021-27103)

 - OS command execution via a crafted POST request to various admin endpoints. (CVE-2021-27104)

Also, Accellion File Transfer Appliance is no longer supported by the vendor.
Lack of support implies that no new security patches for the product will be released by the vendor. 
As a result, it is likely to contain other security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/accellion/CVEs");
  # https://www.accellion.com/sites/default/files/resources/fta-eol.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6f8410d");
  script_set_attribute(attribute:"solution", value:
"Update to version 9_12_416 or later, or 
  upgrade to a more secure platform, kiteworks that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27104");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:accellion:secure_file_transfer_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("accellion_file_transfer_appliance_unsupported.nasl");
  script_require_keys("installed_sw/Accellion Secure File Transfer Appliance", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('install_func.inc');

app_name = 'Accellion Secure File Transfer Appliance';

if (!get_install_count(app_name:app_name))
  audit(AUDIT_NOT_DETECT, app_name);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:443);

report = 'The remote host is running Accellion File Transfer Appliance (FTA) that is End of Life (EOL) on Apr 30th 2021.\n' +
         'It is recommended by Accellion that all customers upgrade to a more secure platform, kiteworks that is currently supported.\n\n' + 
         'Otherwise, update to Accellion FTA version 9_12_416 or later.';
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
