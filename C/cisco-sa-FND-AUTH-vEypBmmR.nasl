#TRUSTED 6b2b0fe3cea5cb4cea0ac4de90ee872647443ae46b0a173b7291571c29c0b58067f29307c0eacfe771ec5f49f3ac82fe197424df67e3e19a0bda0a1021ed7b2e7bb7103fe0c3fb9b5e6e84faf7b51978ff2ce94eeb1615a9d8af482fe9258210e49fb16f3a86ee49965d994f2380ceda23861b8fbe98b6eb1ca8a5300eab01e19bc7e0276495e828d127eb8475c11c54c9f3f5afc7fd45c4208363c54bc2a88c98f3d0d76eca983fa2dd567736b3de6efc362228195baa945c7249aead173aeabaa79c17113c187ef64b332ac3307d1dd835c927d52bf707d30bdb12c33bd2b3b2431d531dc33268f3967527ead5171ebfdead08de00a44805ed245f1f6d9ee391c49fd82f52c5f0bf3632b06f35483d5e1b6c38769677886d3e2dab7a2d2ceb2c375e513e207507368b664530666a05aa71784d7b6ceff4fa3a1852c645b4930a10ec909d262a3cf327338dab0d5a471870d62363a168a4baef8546784fcb69a8e08438f5e2eed509b060e17d4f8552c221e7789c7805171dee38e440bc73cbb3df727b84951943c4130577523540c5b41a73dafbd8634fbfd2687b8f07ea47da3bf5f3e4166bc25fb136314fdc6ee783c2e2d58ac043af1a6e329321b00a1f70bd5ca96b515c6f95bddfcf96b8115ac7b771b520c22c1611d537b2227d0acf2bfad619d9219a00deaf36753694c9ecf42070bc8746291209bb9dcdd16f9307
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143219);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-26072");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt45167");
  script_xref(name:"CISCO-SA", value:"cisco-sa-FND-AUTH-vEypBmmR");

  script_name(english:"Cisco IoT Field Network Director SOAP API Authorization Bypass Vulnerability (cisco-sa-FND-AUTH-vEypBmmR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An authorization bypass vulnerability exists in Cisco IoT Field Network Director (IoT-FND) due to insufficient
authorization in the SOAP API. An authenticated, remote attacker can exploit this, via SOAP API requests, to
bypass authorization and access and modify information on devices that belong to a different domain.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-FND-AUTH-vEypBmmR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?048dec85");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt45167");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt45167");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26072");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:iot_field_network_director_(iot-fnd)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("iot_field_network_director_webui_detect.nbin");
  script_require_keys("Cisco/IoT Field Network Director/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'IoT Field Network Director');

vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'4.6.1'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt45167',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);