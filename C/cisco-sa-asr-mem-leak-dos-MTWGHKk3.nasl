#TRUSTED 70ecf5d38d9b35c7b6abb2ddd850c974f8d7f6e2776151e483336d0c7319d49189654bb75ef4d1a57ed6036b3c39e253406193753b8461d6a8b4b37937be7ee82a826df753a6666cf630354a6701178dde5801cb91fef6fd5b562550ca373f2f252f9b8f4d8b229845ccbfcf664ce06a8c81e289b1881397b9ebd3982fa9a455697cf66ee1abe1cbf0f5844a5b033e95fc1197c9d765478ab1f01f376d9f5b5ca93a08c8cf90b6820d7491a2c6d0c2e2db297c9d213c173a48d4cd25e183b22321ac6d0b746bfd5f28ec784b8868431755e20faedbd08159316a51587d8ca3b7369ca55a9bb299da807ad89f3b5b36ec9b90f21d571b517ca0087d9d58cc855e1164bb4bcdf9ced26cbf083f8a9b49ee1c90414699dccfa4b68011d7f22e190e82d8a577fe4a786aa468b8b4deafa10f0e012d1eec6f055ebef1ad178668b7e728cea6cf405f5a4091487aa0cc79056ac6564bade7dae26fc2b2dcea4759292634fed3964d4ca93a21f3489e89607302c4abdaaaf5e2993bf58a9b8029a583e813960d28ba3a30d57da504997a3940ef921f8ca0f9155cbab674404eaec2f6cc83d9885ad964cfb58ba218e2e8c379dcd1e86fdf154f4e461280cd91aa08acff10cbb9c6133335e84d68df38acaf344feca45628ec7754a8a11f55798ea794863e8fd30abc2af926cce2f5969d2fddc0a2fc6609f71cecb312108288a397c7cb
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145513);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id("CVE-2021-1353");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq83868");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv69023");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asr-mem-leak-dos-MTWGHKk3");
  script_xref(name:"IAVA", value:"2021-A-0046-S");

  script_name(english:"Cisco StarOS IPv4 DoS (cisco-sa-asr-mem-leak-dos-MTWGHKk3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco StarOS Software is affected by a denial of service (DoS) vulnerability
due  to  a memory leak that occurs during packet processing. An unauthenticated, remote attacker can exploit this, by
sending a series of crafted IPv4  packets, in order to cause an  unexpected restart of the  npusim process, resulting
in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asr-mem-leak-dos-MTWGHKk3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95d464a1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq83868");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv69023");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq83868, CSCvv69023");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(401);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asr_5000_series");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/StarOS", "Host/Cisco/StarOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_func.inc');

# only Vector Packet Processing feature affected
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

get_kb_item_or_exit('Host/Cisco/StarOS');

var version = get_kb_item_or_exit('Host/Cisco/StarOS/Version');

var vuln = FALSE;

var major = pregmatch(pattern:"^([0-9]+\.[0-9]+)", string:version);
if (!empty_or_null(major))
    major = major[1];
else
  exit(1, "Unable to extract version number.");

var fix = '21.22.0';
var fix_major = '21.22';

# Vuln if major < 21.22
if (ver_compare(strict:FALSE, ver:major, fix:fix_major) < 0)
  vuln = TRUE;

if (vuln)
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    version  : version,
    fix      : fix,
    bug_id   : 'CSCvq83868, CSCvv69023'
  );
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco StarOS', version);
