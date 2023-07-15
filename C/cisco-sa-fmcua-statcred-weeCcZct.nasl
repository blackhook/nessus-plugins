#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138040);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/06");

  script_cve_id("CVE-2020-3301", "CVE-2020-3318");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo08211");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq50674");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmcua-statcred-weeCcZct");

  script_name(english:"Cisco Firepower Management Center Static Credential Vulnerabilities (cisco-sa-fmcua-statcred-weeCcZct)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Management Center is affected by multiple vulnerabilities. An
unauthenticated, remote attacker can exploit this in order to access a sensitive part of an affected system with a
high-privileged account. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmcua-statcred-weeCcZct
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46010f5a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo08211");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq50674");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq50674 and CSCvo08211");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Require paranoia because FMC is only vulnerable if an attached UA of a certain version is present, which we don't check for
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

constraints = [{'fixed_version': '6.5.0'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
