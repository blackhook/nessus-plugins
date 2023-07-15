#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153589);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-3711", "CVE-2021-3712");

  script_name(english:"Tenable SecurityCenter OpenSSL < 1.1.1l Multiple Vulnerabilities (TNS-2021-16)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is missing
the security patch SC-202109.1, therefore affected by multiple vulnerabilities as referenced in the 1.1.1l advisory:

  - A heap-based buffer overflow condition exists due to the implementation of the SM2 decryption. An
    unauthenticated, remote attacker can exploit this, via specially crafted request, to cause a denial of
    service condition or the execution of arbitrary code. (CVE-2021-3711)

  - An out-of-bounds read error exists in due to improper handling of ASN.1 strings. An unauthenticated, remote
    attacker can exploit this, via a specially crafted ASN1_STRING structure, to cause a denial of service
    condition or disclosure of sensitive information. (CVE-2021-3712)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported patching
information.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-16");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20210824.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202109.1');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'min_version' : '5.16.0', 'max_version' : '5.19.1', 'fixed_display' : 'Apply Patch SC-202109.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
