#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172277);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-2097",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215"
  );

  script_name(english:"Tenable Nessus 8.15.x >= 8.15.4 and < 8.15.9 Multiple Vulnerabilities (TNS-2023-10)");

  script_set_attribute(attribute:"synopsis", value:
"Tenable Nessus running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is between
8.15.4 and 8.15.8. It is, therefore, affected by multiple vulnerabilities in OpenSSL prior to version 1.1.1t:
    
    - An attacker that had observed a genuine connection between a client and a server could use the flaw to send trial 
      messages to the server and record the time taken to process them. After a sufficiently large number of messages 
      the attacker could recover the pre-master secret used for the original connection. (CVE-2022-4304)

    - The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes any header data and the payload 
      data. Under certain conditions, a double free will occur. This will most likely lead to a crash. (CVE-2022-4450)

    - The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. Under certain conditions, 
      the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal pointers to the previously 
      freed filter BIO. This will most likely result in a crash. (CVE-2023-0215)

    - AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of 
      the data under some circumstances. In the special case of in place encryption, sixteen bytes of the plaintext would be 
      revealed. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p). (CVE-2022-2097)
      
  Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-10");
  # https://docs.tenable.com/releasenotes/Content/nessus/nessus2023.htm#8.15.9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea3a4082");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 8.15.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2097");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf_extras.inc');

var app_info, constraints;

app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'min_version':'8.15.4', 'max_version':'8.15.8', 'fixed_version':'8.15.9'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
