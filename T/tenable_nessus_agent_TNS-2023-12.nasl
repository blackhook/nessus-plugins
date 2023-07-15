##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(172636);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-4203",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215",
    "CVE-2023-0216",
    "CVE-2023-0217",
    "CVE-2023-0401"
  );

  script_name(english:"Tenable Nessus Agent 10.x >= 10.2.1 and < 10.3.2 Multiple Vulnerabilities (TNS-2023-12)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus Agent running on the remote host is between
10.2.1 and 10.3.2. It is, therefore, affected by multiple vulnerabilities in OpenSSL prior to version 3.0.8:
    
    - An attacker that had observed a genuine connection between a client and a server could use the flaw to send trial 
      messages to the server and record the time taken to process them. After a sufficiently large number of messages 
      the attacker could recover the pre-master secret used for the original connection. (CVE-2022-4304)

    - The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes any header data and the payload 
      data. Under certain conditions, a double free will occur. This will most likely lead to a crash. (CVE-2022-4450)

    - The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. Under certain conditions, 
      the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal pointers to the previously 
      freed filter BIO. This will most likely result in a crash. (CVE-2023-0215)

    - An invalid pointer dereference on read can be triggered when an application tries to load malformed PKCS7 data. The result of the 
      dereference is an application crash which could lead to a denial of service attack. (CVE-2023-0216)

    - An invalid pointer dereference on read can be triggered when an application tries to check a malformed DSA public key by the 
      EVP_PKEY_public_check() function. This will most likely lead to an application crash. (CVE-2023-0217)

    - A NULL pointer can be dereferenced when signatures are being verified on PKCS7 signed or signedAndEnveloped data. In case the hash 
      algorithm used for the signature is known to the OpenSSL library but the implementation of the hash algorithm is not available the 
      digest initialization will fail. (CVE-2023-0401) 

    - A read buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking, which
      might result in a crash which could lead to a denial of service attack. (CVE-2022-4203)
    
      Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent 10.3.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin", "nessus_agent_installed_macos.nbin", "nessus_agent_installed_linux.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Tenable Nessus Agent');

var constraints = [
  { 'min_version':'10.2.1', 'fixed_version':'10.3.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);