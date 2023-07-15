##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(172140);
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

  script_name(english:"Tenable SecurityCenter 6.0.0 Multiple Vulnerabilities (TNS-2023-07)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
running 6.0.0 and is therefore affected by multiple vulnerabilities in OpenSSL prior to version 3.0.8:
    
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
      might result in a crash which could lead to a denial of service attack. (CVE-2022-4203)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-07");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2023.htm#2023031-6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a72657df");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202303.1');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
    { 'min_version' : '6.0.0', 'max_version': '6.0.0', 'fixed_display' : 'Apply Patch SC-202303.1-6'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
