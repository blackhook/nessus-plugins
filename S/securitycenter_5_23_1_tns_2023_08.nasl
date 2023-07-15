##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(172139);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/06");

  script_cve_id(
    "CVE-2022-1292",
    "CVE-2022-2068",
    "CVE-2022-2097",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215"
  );

  script_name(english:"Tenable SecurityCenter <= 5.23.1 Multiple Vulnerabilities (TNS-2023-08)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
running a version between 5.21.0 and 5.23.1 and is therefore affected by multiple vulnerabilities in OpenSSL 
prior to version 1.1.1t:
    
    - A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient to 
      recover a plaintext across a network in a Bleichenbacher style attack. To achieve a successful decryption an 
      attacker would have to be able to send a very large number of trial messages for decryption. The vulnerability 
      affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. (CVE-2022-4304)

    - Vulnerability in the Enterprise Manager Ops Center product of Oracle Enterprise Manager (component: 
      Networking (OpenSSL)). The supported version that is affected is 12.4.0.0. Easily exploitable 
      vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Enterprise 
      Manager Ops Center. Successful attacks of this vulnerability can result in takeover of Enterprise 
      Manager Ops Center. (CVE-2022-1292)

    - The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes the name, any header data and the 
      payload data. It is possible to construct a PEM file that results in 0 bytes of payload data. In this case 
      PEM_read_bio_ex() will return a failure code but will populate the header argument with a pointer to a buffer that 
      has already been freed. If the caller also frees this buffer then a double free will occur. This will most likely lead 
      to a crash. This could be exploited by an attacker who has the ability to supply malicious PEM files for parsing to 
      achieve a denial of service attack. The OpenSSL asn1parse command line application is also impacted by this issue. 
      (CVE-2022-4450)

    - The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. It is primarily used 
      internally to OpenSSL to support the SMIME, CMS and PKCS7 streaming capabilities, but may also be called directly by end user 
      applications. The function receives a BIO from the caller, prepends a new BIO_f_asn1 filter BIO onto the front of it to form a 
      BIO chain, and then returns the new head of the BIO chain to the caller. Under certain conditions, for example if a CMS recipient 
      public key is invalid, the new filter BIO is freed and the function returns a NULL result indicating a failure. However, in this 
      case, the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal pointers to the previously 
      freed filter BIO. If the caller then goes on to call BIO_pop() on the BIO then a use-after-free will occur. This will most likely 
      result in a crash. (CVE-2023-0215)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-08");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2023.htm#2023031-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a45cd398");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1292");

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
    { 'min_version' : '5.21.0', 'max_version': '5.23.1', 'fixed_display' : 'Apply Patch SC-202303.1-5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
