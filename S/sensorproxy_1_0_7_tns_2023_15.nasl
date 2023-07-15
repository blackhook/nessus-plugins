#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173397);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2022-2097",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215"
  );

  script_name(english:"Tenable Sensor Proxy < 1.0.7 Multiple Vulnerabilities (TNS-2023-15)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Sensor Proxy application running on the remote host is 
version 1.0.6. It is, therefore, affected by multiple vulnerabilities in OpenSSL prior to version 1.1.1t:
    
    - An attacker that had observed a genuine connection between a client and a server could use the flaw to 
      send trial messages to the server and record the time taken to process them. After a sufficiently large
      number of messages the attacker could recover the pre-master secret used for the original connection. 
      (CVE-2022-4304)

    - The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes any header data and 
      the payload data. Under certain conditions, a double free will occur. This will most likely lead to 
      a crash. (CVE-2022-4450)

    - The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. 
      Under certain conditions, the BIO chain is not properly cleaned up and the BIO passed by the caller 
      still retains internal pointers to the previously freed filter BIO. This will most likely result 
      in a crash. (CVE-2023-0215)

    - AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not 
      encrypt the entirety of the data under some circumstances. In the special case of in place encryption, 
      sixteen bytes of the plaintext would be revealed. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). 
      Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p). (CVE-2022-2097)
      
  Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-15");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/downloads/sensor-proxy");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Sensor Proxy version 1.0.7 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2097");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4304");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:sensorproxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sensorproxy_installed.nbin");
  script_require_ports("installed_sw/Tenable Sensor Proxy");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Tenable Sensor Proxy');

var constraints = [
  { 'min_version' : '1.0.6', 'max_version' : '1.0.6', 'fixed_version': '1.0.7'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
