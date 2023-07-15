#TRUSTED 409f7f6bed6f3e0baba9ce188bb9bf882146b0115883ac23d07b5a3c9ab45940a84acb56a28677fe1960e1e02576a8426ea700e211e033e257db91c5ee225ddfa3dfea546a990d1dd1953b9e98e028807ba43d3eb1d1a9941ebc60c012ac54d5f37eb3a219bd4bfd43cae1281d7699c948c1756f72c65a5ffbbb59c5ef27f5e10becd0efc9c462acc2e26cbf72bd6718dc5731c0736b9e0bbfb840a0fc600c2f8119f3f2488b0d45d43ed87f59b237e74dfd099d10c7af587688dc97dec561b3b37d1152f9eb65572fc11bcec7f2c2fb9e114f64b6a7ddd13320206e1d9e52cb659c2cc84c568899c38e307565a091802e85340dec90153d78a8e56d2c00041e4b4759e7d0c3685fefe80fe548451013f9eef8919a3251ecd6e60812e12c36370b41a8d3f97e32ed206c1eaecd1ad60666563ed1bf9fe57b94201859e2c5b0b4ed684a7da1bcf178ef69ff22cd090ba99b478dcbc297532d91860f9a64885a509fd85c10411321d01e32229797caad62b568eda5a8a941e46966fdb9f954583e9507ad1a8af8e6dc7df477b65b41a5d9d76979a7278a7ce40c5d0667ece59b67b14ab17d505f5f32cc1d99c12c80d3dc362e7bcc242228da13e9823946e8a7c45ea2f369d5909ae50a5ec6a002cc1a008b97be8bf38af4fb8e93c9c130fc0c299b5911c6e648e7bb192efaeba4a891e97d457c6c06608269d19fa7f9df14be61
#TRUST-RSA-SHA256 5b231cb62987a3b75a2bd1a2fff7787888361c5a8c5ffb3d6dbc74e7e07a6c9054484ff3e3e7094c54ac48e8370bb65c3fea051449d19cd33c5bac10362fabf9456786139c0854c00800f2a56a0a2a062ba65a59c056e08cda693e37638cc9955bafc46b0082875582e9d9695ebb86feded0867fece94aa187640c82ea39ee89abf5d879f26015cb184ceee47bba309d5e3905be37c05bd899f59bf82ddc6637937db79892978c2e8768b5fc059e91ac541e892750064ed7d0fc5b5062f872468565565c9ad5d5be7c5d2f97e992eb3622d44e05c209e1f50539864ffb2d4220e0d27bc23930241a5d417d2e0f1884de09c2847883af5777c1b2f6dc358023ea69ce0afe2117862a223338b32215aa4c73355a35809c5525f178779757e5e64a3fcd052e3b07c0b6d8a3251c93f3eecbadae9054eb8888cbc7e34798786fad87d40286869ac4dd7a02ede107be988948cafc95be1a7023f9d3d079daf8ca8c63820380751e25d984f1a03fc930800dc9447943fe2d69913e52cf44ac607cb1171906725dea3c09f4be53f32bd956ade0a8392ac7f845e93a51f9c4d08a0284d1e532257238528ee1c61988c1ad8b41313122cc1601df2d071a98f90e62d7fb5985501e90f9e360612c5ccf8cf0b94b214fda66c40728fff74fa43318e05467adcfc445743c7ff9003424bd40342ac255eebb42f33453318e7272c3239880eb80
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142363);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3352");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq43920");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-hidcmd-pFDeWVBd");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software Hidden Commands (cisco-sa-ftd-hidcmd-pFDeWVBd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability in its 
CLI component which allows access to hidden commands. An authenticated, local attacker could exploit this to access 
these commands and make configuration changes to various sections of an affected device which shouldn't be exposed in 
the CLI.  

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-hidcmd-pFDeWVBd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce5028d0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq43920");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq43920");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3352");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(912);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'6.3.0.6'},
  {'min_ver':'6.4', 'fix_ver':'6.4.0.10'},
  {'min_ver':'6.5', 'fix_ver':'6.5.0.5'},
  {'min_ver':'6.6', 'fix_ver':'6.6.1'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq43920',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
