#TRUSTED 56143ade1c06eb284d45516b4615f688f6cebbc2e4ac504862c6b098415effabaaaf224337e70fe0e5d56944d951fdab3a13a2260b6ad693c557228ac4d4b5f38a0eabf72688549d4ea4cacb3a5d9c4f84aa5c8b88d196acf71aad23b6d8c7673209213591c1cd76ae908abceb6703f3f24a7645619d0c92e475218b71d98cdef9af8f6544158c06b84a80017c76bb8bdbd43aaea00af3d599b22a5f50bc5532bd57e2c3a671732f295bfd6b6ef3b5c2517bd628f6bf3706f45721930b81cd9ef5800db6ea7d1a09ec701c8a857c509828f4ba79b4b237eaac896833bf6b8769b1047a067c85de8e0a16f3fbc5f8bdff2cae0f828106855c271990995c653738b988eccb5bc6c53ddbdfa89e425e944ae5321068777795cba2512815f91cbbec1209d72a48454de9d22a50d9a3670eaec7e22177d2bd98d6c6df5d4551aa1dd20caefd714781498a05d1c19dda3172f39fbfd330bd1d2beda9404ec6de152dd227ddec59c023f89fe7abd6e9587ea206c7dfe390d921aff5ba93dc230407bd8514176d91694162a517f5408a16872146179cfc35e028a65cfd73b03b70bfb5e160136ffde472e21672018f3e4ed30701283161769cb04efc7262472304c65161c48afb7104b5e8d2f572e1fb85697f52b74a9255a6f51ef13233f7aca29f787798776f7a6fac9e5ddab65e79e421a65ecaa8597f44e1c697de5d7d3e19d44722
#TRUST-RSA-SHA256 0b95cdb7c615e5a911f4ae432c04c1255da6462ab4647a2a2240c6f27b8c9b349d2cdfabf0aaeade6edddf1652e2017899956544b12c50949d88d74940e5e81e2b43d75c19dce6e89098f9fc3d6610d13c78e521cdf24b0607df54c9824be7482a1e81bc4c99cd713abbde410e51c83e2635becfccfa38fc3fe13761b604293a1874edfa4732e0c58dfd3d0b736f825e02c2d7d2c9d0e8d82ca525b2f706b30d57a109fb585eb906a491ec5db4ffa103564521f1d098cd2034ef748cea5152bded914bc984ce43bf221d0c35b65e2020ce3cb60c8ca8bbb4ecdc254d9476172df2079d802be5bc3882d766765b38858255387a8687902576b6fed52d4217afd77fe89c44ad7ca52e349c51db33289dfe43e71520b988c9b21a960cef79001512cba7289bb90008c39287c38f525123a0a37134c549dc51a08f8c176804961ba060652f6cf2d7c319295754f9fe923b4a94c1e898e5cd4c711777d5d89a5a539ba445d699f862ec63f45a8d1de06c422c0074f2506c483ff09d09467fce887c9aad6fde9dd753e53a6ab7f675e62f0c42a00092d89a6ebb1fcc40511e6de7d891cfd85546e062c79968efb94932c132e6dfad18389fde0c156b4c60f9f909306b9c8894b8df435df01455fb643746873f5853c2bd60561df64fbe01e41c2a2f41d91ffe51f257281d8127745db3a2e4b72778c0f3d7bce8434a8bab517810c4a7
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167271);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20946");
  script_xref(name:"IAVA", value:"2022-A-0487-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb66761");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-gre-dos-hmedHQPM");

  script_name(english:"Cisco Firepower Threat Defense Software Generic Routing Encapsulation DoS (cisco-sa-ftd-gre-dos-hmedHQPM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service vulnerability. An
unauthenticated, remote attacker can exploit this, by sending a crafted GRE payload through an affected device, to cause
the affected device to restart.

Please see the included Cisco BID and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-gre-dos-hmedHQPM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65aa0581");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb66761");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(122);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

# Unable to determine if configured to bypass the detection engine for GRE-tunneled traffic
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');

var vuln_versions = make_list(
  '6.6.0',
  '6.6.0.1',
  '6.6.1',
  '6.6.3',
  '6.6.4',
  '6.6.5',
  '6.6.5.1',
  '6.6.5.2',
  '6.3.0',
  '6.3.0.1',
  '6.3.0.2',
  '6.3.0.3',
  '6.3.0.4',
  '6.3.0.5',
  '6.4.0',
  '6.4.0.1',
  '6.4.0.3',
  '6.4.0.2',
  '6.4.0.4',
  '6.4.0.5',
  '6.4.0.6',
  '6.4.0.7',
  '6.4.0.8',
  '6.4.0.9',
  '6.4.0.10',
  '6.4.0.11',
  '6.4.0.12',
  '6.4.0.13',
  '6.4.0.14',
  '6.4.0.15',
  '6.5.0',
  '6.5.0.2',
  '6.5.0.4',
  '6.5.0.1',
  '6.5.0.3',
  '6.5.0.5',
  '6.7.0',
  '6.7.0.1',
  '6.7.0.2',
  '6.7.0.3',
  '7.0.0',
  '7.0.0.1',
  '7.0.1',
  '7.0.1.1',
  '7.0.2',
  '7.0.2.1',
  '7.0.3',
  '7.1.0',
  '7.1.0.1',
  '7.1.0.2'
);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwb66761',
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_versions:vuln_versions
);
