#TRUSTED 5238f7e76e3e074cc1e1dce73ca02647700f12ca7d0003813630d0e94f9f00ab5ac2bd19755e09ca2d3ef209a30d8deeb3adf06446080ee1c73784a6336f2cf0e7f2c7ac32130a25257469e4a2380a67b97fc16660d962de9a1c05e55215722d5874de726029883ad4c22444f50798ed3192279934aa16e560c47f4e6200d90bc8b6e580eb873e62da19881b496cdb4c4111dd5d8c23961c775ac775a0118daa6e5c7999b1d6700101970c558305bf50d8e68ff488b38fe51bd7c4d0b5cc5fce0d0f5377257f5f6352098ddc8e604ab1c946404baa01e1cfa3f3cb82ff3419bbf6a35f553c4f9c5246ee1813e31a31127d2b0de3e5e36d0e16b9d48f7a4d668ec41b6f3ff562043146ba81ad3c7104d3c99c3c3cf210f29cdba19d4c202b3f2ea022d172aace1bf34611fcf60031b85f6a7c38f06a66f2ad11a643efff08de33404fd4c34de3b431b35831fef4b0f71dba8f9fcb9be18e31ea86b18728e9fb26da133d1a424cdaaee153b3d5684780a12fdabd68dca5941bb014fe972fe649f655fcbc574d975df1023a7c1fc878bd9186032bfcbb85afd071b2b80b11b8f560401e301866331849ed9e9f847859686fe0dcb45f6c35b6693f8d8385fd59cdb08812ccd4e9cecd80ed80d231b1ba473124ef844640660fb8393620e9fe733cd1e10756adba1c28a484693bbab4721ba1e15931b0160d5185a2e034b7fac7abe2
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139806);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_cve_id("CVE-2019-1836");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo80695");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-fabric-traversal");

  script_name(english:"Cisco NX-OS Directory Traversal (cisco-sa-20190501-fabric-traversal)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco NX-OS installed on the remote host is affected by a directory traversal vulnerability in its
system shell due to incorrect symbolic link verification of directory paths. An authenticated, local attacker can 
exploit this, to overwrite system files whose access should be restricted to the root system user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-fabric-traversal
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8edbc36");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo80695");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory cisco-sa-20190501-fabric-traversal");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1836");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
if ('Nexus' >!< product_info.device || product_info.model !~ '^90[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'affected');

# Advisory doesn't state affected versions.
# Entry below is sole entry in BID affected versions.
version_list = make_list('14.0(3d)');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo80695'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list);

