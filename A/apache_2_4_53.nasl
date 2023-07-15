#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158900);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/15");

  script_cve_id(
    "CVE-2022-22719",
    "CVE-2022-22720",
    "CVE-2022-22721",
    "CVE-2022-23943"
  );
  script_xref(name:"IAVA", value:"2022-A-0124-S");

  script_name(english:"Apache 2.4.x < 2.4.53 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.53. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2.4.53 advisory.

  - mod_lua Use of uninitialized value of in r:parsebody: A carefully crafted request body can cause a read to a
    random memory area which could cause the process to crash.  This issue affects Apache HTTP Server 2.4.52
    and earlier. Acknowledgements: Chamal De Silva (CVE-2022-22719)

  - HTTP request smuggling: Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are 
    encountered discarding the request body, exposing the server to HTTP Request Smuggling Acknowledgements: James 
    Kettle <james.kettle portswigger.net> (CVE-2022-22720)

  - Possible buffer overflow with very large or unlimited LimitXMLRequestBody in core: If LimitXMLRequestBody is set to 
    allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems an integer overflow happens which later 
    causes out of bounds writes.  This issue affects Apache HTTP Server 2.4.52 and earlier. Acknowledgements: Anonymous 
    working with Trend Micro Zero Day Initiative (CVE-2022-22721)

  - Read/write beyond bounds in mod_sed: Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows
    an attacker to overwrite heap memory with possibly attacker provided data.  This issue affects Apache HTTP
    Server 2.4 version 2.4.52 and prior versions. Acknowledgements: Ronald Crane (Zippenhop LLC)
    (CVE-2022-23943)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement2.4.html");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.53 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

var constraints = [
  { 'max_version' : '2.4.52', 'fixed_version' : '2.4.53' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
