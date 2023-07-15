#TRUSTED 90f44d6896fe1d6ad4f2c24349539cdbf791688b23b999e04f3cccaf43be27b53970b552d654e16aea326ed327be5cc8858fa330b6c66a29399e459cb6ebe6863d754679c031a1233d75aecce2a7f84991b54a7bbfb8476876260964e620c3e94329aff3d486ddbc55dcbf7426b72c3a22e9c6832dac87c83dd568df6e4288979293048f4e4b17ff82bf62741a072116bfde5cb3628e5dc61edd4d8bf909075b42fa206db0a8e697834f146ec0e7b6cecc3b2450fad91e232c43c979fad307afbe1102b3c55c8a83db53f5b0a6828e35f5f97458d9224f4f25f3f594f403d08ffe225b97961718ba543a34207200c7a36f07bed238a8823ba0da6b4e1918507cb688145a1d044152e9327bce7aa7ca495ae7b0b89e3fde7fe5a44559ed5b9d0f1afa13dd2df146b6e3612e11b8d164bc9da1bc62b69d168cc59b58387db6f4c66eaabf5f2ad892cc4d58e64fef923c949ba204d21fd7da78a370cac7221e563b6923cfef8d06b5969d5f14990edf38bcf0e6d1c468c61ddc7927b1285cd64272bf12f5492f2bd99a54c56ac0f5c36459b7c51c433d75cc8f7c4d6663c8410b43fa8c81184dc3ea53b39329575276983956c41628c34f2f3fd200cec6d9f90df07a0e1bdeef2eaccbb1690f6c4355fe44a1f871954400e84852747438c65861dc4b80403f4743536f58660a6ea7e4daa98ccafb6ffc93b3f9d8d1bb4912933c3e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137850);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/24");

  script_cve_id("CVE-2020-3354", "CVE-2020-3355", "CVE-2020-3356");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt05178");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt10966");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt10970");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-stored-xss-VyE4bNAh");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-stored-xss-yJyqBJGU");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-stored-xss-eUyGPqxm");
  script_xref(name:"IAVA", value:"2020-A-0279");

  script_name(english:"Cisco Data Center Network Manager Multiple Stored Cross-Site Scripting Vulnerablities (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A stored cross-site scripting (XSS) vulnerabilities exists in web-based management interface of Cisco Data Center
Network Manager (DCNM) due to improper validation of user-supplied input before returning it to users. An
unauthenticated, remote attacker, administrative credentials can exploit this, by convincing a user to click a
specially crafted URL, to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-stored-xss-eUyGPqxm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37e25ad3");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-stored-xss-VyE4bNAh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb1a5d8b");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-stored-xss-yJyqBJGU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbe408e0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt05178");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt10966");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt10970");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt05178, CSCvt10966, CSCvt10970");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3356");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl", "cisco_prime_dcnm_web_detect.nasl");
  script_require_ports("installed_sw/Cisco Prime DCNM", "installed_sw/cisco_dcnm_web");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_dcnm_web::get_app_info();
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'max_version' : '11.3.1.0', 'fixed_display' : 'Please see advisory' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
