#TRUSTED 4e97c4928847beec536ef03b7a04d9e077370150aeee56ed14a8c0f72265b68a6409066fef8c6fbc814220122ca91dc9d0a89bc7b74bedfbf08575de2a78c9ff90455302021c26305eb5d4533384d917a63fd92c845077db6d786eefc4e7f731f8a61c9299304ffba3748ce24ad35722908ab6123003d7dda1fcb14f0cde19241c5dd0eedd99487d0f81efa64cf8369fbe0db77ae81da1404a8100d95704ec7802790c723eefa27cc0b56c3b0fbd2f82c522532666225e749e72101118a4fb7f4f1eac5f55b3a2ca4e1929305b7744c233526415632d4ce6710a0f17ce06b0df6938fda74008ce869ccfd309d3390572012f9da3b6c1048e6939e064aa80916c9fc9bb557d5033d90c77c5cae312b8fe7d66ac0589b4ee3a5c97913a58b789d3aeb2e131128d6e7e7443232fd71ef247b76666252706f110fd53bc08554bcc066d13f511a392b05f6aa8b7b4868d9e53fbb3b650cdc3a94a0139167295a9d8e44854472b6157ec19bd589b1066c90c2e3d46cc09325ae088528f4b7a4040735ac80ed4be8529e807023af6017300bd2852cfe17be1ad8c918b2c5bee87c5ddd97acbc494fa97feb9414dd8746faf423e69470d12d1d525d38482775f617ea35e2a9c76af0a4b0fd0385bbabdc9f44338e7f71ed660b7ab23fecdedebd4c59cfe847dfe3e04bfa06722301c90a693d64e3629f5c616823b6880565583586a2754
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134713);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/22");

  script_cve_id("CVE-2019-1738", "CVE-2019-1739", "CVE-2019-1740");
  script_bugtraq_id(107597);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb51688");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc94856");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc99155");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf01501");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-nbar");

  script_name(english:"Cisco IOS Software Network-Based Application Recognition Denial of Service Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is
affected by following multiple vulnerabilities

  - Multiple vulnerabilities in the Network-Based
    Application Recognition (NBAR) feature of Cisco IOS
    Software and Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to cause an affected
    device to reload.These vulnerabilities are due to a
    parsing issue on DNS packets. An attacker could exploit
    these vulnerabilities by sending crafted DNS packets
    through routers that are running an affected version and
    have NBAR enabled. A successful exploit could allow the
    attacker to cause the affected device to reload,
    resulting in a denial of service (DoS) condition.
    (CVE-2019-1738, CVE-2019-1739, CVE-2019-1740)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-nbar
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b838dda");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc94856");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc99155");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf01501");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvb51688, CSCvc94856, CSCvc99155, CSCvf01501");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1740");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.5(3)S',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)M',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M5',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M5a',
  '15.5(3)SN0a',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(2)S2',
  '15.6(1)S3',
  '15.6(2)S3',
  '15.6(1)S4',
  '15.6(2)S4',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T0a',
  '15.6(2)T2',
  '15.3(3)JNP',
  '15.3(3)JNP1',
  '15.3(3)JNP3',
  '15.6(1)SN',
  '15.6(1)SN1',
  '15.6(2)SN',
  '15.6(1)SN2',
  '15.6(1)SN3',
  '15.6(3)SN',
  '15.6(4)SN',
  '15.6(5)SN',
  '15.6(6)SN',
  '15.6(7)SN',
  '15.6(7)SN1',
  '15.6(7)SN2',
  '15.3(3)JPB',
  '15.3(3)JPB1',
  '15.3(3)JD',
  '15.3(3)JD2',
  '15.3(3)JD3',
  '15.3(3)JD4',
  '15.3(3)JD5',
  '15.3(3)JD6',
  '15.3(3)JD7',
  '15.3(3)JD8',
  '15.3(3)JD9',
  '15.3(3)JD11',
  '15.3(3)JD12',
  '15.3(3)JD13',
  '15.3(3)JD14',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.3(3)JPC',
  '15.3(3)JPC1',
  '15.3(3)JPC2',
  '15.3(3)JPC3',
  '15.3(3)JPC5',
  '15.3(3)JE',
  '15.3(3)JPD',
  '15.3(3)JF',
  '15.3(3)JF1',
  '15.3(3)JF2',
  '15.3(3)JF4',
  '15.3(3)JF5',
  '15.3(3)JG',
  '15.3(3)JG1',
  '15.3(3)JH',
  '15.3(3)JI',
  '15.3(3)JK2'
);

workarounds = make_list(CISCO_WORKAROUNDS['nbar']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvb51688, CSCvc94856,  CSCvc99155 and CSCvf01501',
  'cmds'     , make_list("show ip nbar control-plane | include NBAR state")
);

cisco::check_and_report(
  product_info      : product_info, 
  workarounds       : workarounds, 
  workaround_params : workaround_params, 
  reporting         : reporting, 
  vuln_versions     : version_list
);
