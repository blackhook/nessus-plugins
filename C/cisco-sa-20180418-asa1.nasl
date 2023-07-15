#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109404);
  script_version("1.7");
  script_cvs_date("Date: 2020/01/17");

  script_cve_id(
    "CVE-2018-0227",
    "CVE-2018-0228",
    "CVE-2018-0229",
    "CVE-2018-0231",
    "CVE-2018-0240"
  );
  script_bugtraq_id(103934, 103939);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg40155");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf63718");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve18902");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve34335");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve38446");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg65072");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh87448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve61540");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh23085");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh95456");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asa1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asa2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asa3");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asaanyconnect");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asa_inspect");

  script_name(english:"Cisco ASA Multiple Vulnerabilities (cisco-sa-20180418-asa1 / cisco-sa-20180418-asa2 / cisco-sa-20180418-asa3 / cisco-sa-20180418-asaanyconnect / cisco-sa-20180418-asa_inspect)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Adaptive Security
Appliance (ASA) software running on the remote device is affected by
multiple vulnerabilities. Please see the included Cisco BIDs and Cisco
Security Advisories for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3022fd51");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d86bee0f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asa3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72e6e924");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asaanyconnect
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?496f5656");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asa_inspect
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcd24031");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg40155");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf63718");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve18902");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve34335");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve38446");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg65072");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh87448");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve61540");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh23085");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh95456");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20180418-asa1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  model !~ '^411[0-9]($|[^0-9])'     && # Firepower 4110 SA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model != 'v' # ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCvg40155, CSCvf63718, CSCve18902, CSCve34335, CSCve38446, CSCvg65072, CSCvh87448, CSCve61540, CSCvh23085, and CSCvh95456';

if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7.20)";
else if (version =~ "^9\.0[^0-9]")
  fixed_ver = "9.1(7.20)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.20)"))
  fixed_ver = "9.1(7.20)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.27)"))
  fixed_ver = "9.2(4.27)";
else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(4.14)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(4.14)"))
  fixed_ver = "9.4(4.14)";
else if (version =~ "^9\.5[^0-9]")
  fixed_ver = "9.6(4.6)";
else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(4.6)"))
  fixed_ver = "9.6(4.6)";
else if (version =~ "^9\.7[^0-9]" && check_asa_release(version:version, patched:"9.7(1.24)"))
  fixed_ver = "9.7(1.24)";
else if (version =~ "^9\.8[^0-9]" && check_asa_release(version:version, patched:"9.8(2.28)"))
  fixed_ver = "9.8(2.28)";
else if (version =~ "^9\.9[^0-9]" && check_asa_release(version:version, patched:"9.9(2.1)"))
  fixed_ver = "9.9(2.1)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver
);

