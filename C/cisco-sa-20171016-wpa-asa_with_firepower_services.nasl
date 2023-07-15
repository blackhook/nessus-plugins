#TRUSTED 3c32f3c2bdaf5f20e0caf53123aefdf2648988c86afdcc94f8e09785334b1b4d198aab3dabab8864f52ed1ac0c736b19008636dd447d5bac5535aa21e1e8bb1050637e30b670147feb534e6f7ea8e2b178cca6f763916beeb29d942bae06448be2ece162ac99303e1ceec4a92b9f1e2586742fdb82ad351f2430e0596d38b494dcf9f1686742f0007375dbd84f69e1ee004fabbca0a9c6edd473c5c35ae55e19aea97ad665393acc76aa72872b824beaee8ecf4360ea1f941ec2209dcaa47a6b1c6727547b3f15dadaa5d8bb570c27521cffabc5c901ad7c2b08ea61daa449e199309327ffba15d80a4cfcb487a7cf144e7daba5956c6b99ee0cb2d063c383604cbef7389e7f899268e62a732a411ff205fc26f5dfa37a9b56ac0af91118e04c44a45044d07dfcd0d050d46c22f2af8a6d1f1c95ee6d601616619d9ac00223b7ecce042d5f17380585c6a3a2eff5719e6589170010120f708ac352bdb36060c435f2d3ec96743ddae0b12d836e16dcb25739154930fd205c5f806f2d0da8d9e4a1175d7149de99d91ada48ed75d31a2fdc9fb84491705352ebeef3d847915bcbfa6c55ca24a3d9379177a46c04c0e5df791784f5018922576b74f9247e4fdb2bccf44d5cb0d545827d6d41f7bd6f9278f91daf4d5d138631c483649a33b1ae2d79059781b80ce986997782c69a9f00bed82c58f4c032fecfdb564e8fca33b734
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103856);
  script_version("1.14");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id(
    "CVE-2017-13077",
    "CVE-2017-13078",
    "CVE-2017-13079",
    "CVE-2017-13080",
    "CVE-2017-13081",
    "CVE-2017-13082",
    "CVE-2017-13084",
    "CVE-2017-13086",
    "CVE-2017-13087",
    "CVE-2017-13088"
  );
  script_bugtraq_id(101274);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"IAVA", value:"2017-A-0310");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg10793");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171016-wpa");

  script_name(english:"Cisco ASA FirePOWER Services Multiple Vulnerabilities in Wi-Fi Protected Access and Wi-Fi Protected Access II (KRACK)");
  script_summary(english:"Checks the Cisco ASA with FirePOWER Services version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco ASA with FirePOWER
Services is affected by multiple vulnerabilities related to the KRACK
attack. Please see the included Cisco BIDs and the Cisco Security
Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171016-wpa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?deb024bb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg10793");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
 CSCvg10793 CSCvg10793 CSCvg10793 CSCvg10793 CSCvg10793 CSCvg10793 CSCvg10793 CSCvg10793 CSCvg10793 CSCvg10793.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13082");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("ccf.inc");
include("misc_func.inc");
include("global_settings.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

# Affected Models:
# 5500-X Series
if (
      model !~ '^5506W-X'
   ) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product model");

version = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");
if (isnull(version)) audit(AUDIT_HOST_NOT, "affected");

version = version[1];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , version,
  'bug_id'   , "CSCvg10793, CSCvg10793, CSCvg10793, CSCvg10793, CSCvg10793, CSCvg10793, CSCvg10793, CSCvg10793, CSCvg10793, CSCvg10793"
);

if(ver_compare(fix:"8.3.130.0", ver:version, strict:FALSE) < 0)
{
  cisco::security_report_cisco_v2(reporting:reporting);
}
else
{
  audit(AUDIT_HOST_NOT, "affected");
}
