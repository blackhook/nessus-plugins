#TRUSTED 07da0eceddfbd628eeb99169e537521127284a1d0d3947496dbf4db05136b44a7611b1efd156a3b9f873d8cca7fed515b0e5d92b7325bbc57876363724f45b9d58692c524c362e4d0c6d435ec64cb4870f075b75b307c49bf89c2df69eacb78f5f89fafe8a440ad203adaa0c4b6356945adfc30ef638731b92ee7a1ece845a32b247ab782c86366efbdb2749665229b8620442a07a941870c5eac62dc29b501f727ba085dedcad4bcd27bc26b6b0c1b4da30b6478113b96f6091026a63a6066fda938db39415e71f766a051a075d456c5a731296f41c356559d4abef72605f4edc8248b829325890e44b781db419c346fd00d4ea1be28cbd1d09cd75e097def233bf2045e443a76cebdfe7ba36bfe4fd6723de8304daa828138240c936afcde685f36823576fd5ab8a610fc22e181101d00e1c1f1687c2b4b9b42072db66bc8f9e0fe9829fac0cc48940599399c44458ff38150e2d674a006138efebf8344e57a1ebb031ea56424b066f02756eeb8892730f5e41843ce6dba1f02eb730786b3db578498eacf47e3d7357f1f6b8c9affd706dfabc12315b96cc79e9b8fe08537b85b3f7931779e1beba848ad38a52984146ea595b31766d8341a7987d09ec311d32c7f98ba93a6867443ebab9fb5292ce6600272c60706c5688ea05b5bd89ff25674a0973c9e67fad212013cf293568e9ce0b85bc146ad135462e0473ce94e173
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141438);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_cve_id("CVE-2020-3264", "CVE-2020-3265");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50619");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs47117");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwpresc-ySJGvE9");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwanbo-QKcABnS2");

  script_name(english:"Cisco SD-WAN Solutions < 19.2.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Cisco Viptela hosted on the remote server is prior
to 19.2.2. It is, therefore, affected by multiple vulnerabilities:

  - A privilege escalation vulnerability exists in Cisco SD-WAN Solutions due to insufficient input validation.
    An authenticated, local attacker can exploit this, by sending a crafted request to an affected system, to
    gain root access to the system. (CVE-2020-3265)

  - A buffer overflow condition exists in Cisco SD-WAN Solutions due to insufficient input validation. An
    authenticated, local attacker can exploit this, by sending crafted traffic to an affected device, to
    gain access to information that they are not authorized to access and make changes to the system that
    they are not authorized to make. (CVE-2020-3264)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwpresc-ySJGvE9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57b99f17");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwanbo-QKcABnS2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d49d1bd3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs50619 or CSCvs47117");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3265");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_solution");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');
vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '19.2.2'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50619, CSCvs47117',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
