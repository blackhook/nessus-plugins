#TRUSTED 8390f248b327d8021c26b7d9a9dbbb5c424a1fd48b17703bb65665a7527f534f989551ff9d90b5998a7fbb9be7611bae3bd7f025073672995daf20d67340d9a6b6dd8f1024a7191c65be946d6e22e190961d2814381cef42a72148721590f1f38979595f727f60df8b49f7af90e5734add789b84f436b62a83b600e1d3db955effada6da24ef484fcb90100cdf558f1f1ce3835d91133c0cb3c5f768698d98f8bc5ec6dc1f73a16270e8235e1bae6bfda05ab730f74e1ac3b55d6a250148eb372b110868f80cacaa50fa794bd72a931b1fd77a7a6cc9aa2dcf34d0b8a4f4f80f575db21ffd279f6bc8d8345a05c7b277b020c9230f999953bec446e051b2fa3df564213ecd745be14618d4b594b12b91b940370f0871f1b89ef19fe12d17105b27fe3da823030766a07ef7f99138391bd5fad4449b6f28c09680d9499fc03d3b9205c5cd9fd25bd5f174b8bd529ebf353ef56d4ccb961baeee096745f772f80b3b2e789d77303386c300733418bb5ecad81df7af0ae37d03e874a817b90a071369c77a23603b9dcf34845f55eadce0e1ede067a6cebef117bb956ab67484c00754f186d11ad4490a068b078ffc50b174031a3b06ec568c887552d65cef81ca8240e94485477592eb7be2e3da0af7e6341cecec46614d1b70c8abe4852ecafaa98431771369e13310b1a328e06ac4bfac656be2dbf7c959588f3b79471f5853f3
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148091);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1381");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu78908");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-BLKH-Ouvrnf2s");

  script_name(english:"Cisco IOS XE Software Active Debug Code (cisco-sa-XE-BLKH-Ouvrnf2s)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-BLKH-Ouvrnf2s
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd603840");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu78908");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu78908");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1381");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(489);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if (model !~ '^IR1101')
    audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvu78908',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
