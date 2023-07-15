#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110686);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0296");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi16029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180606-asaftd");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2019-0741");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Cisco ASA Web Services DoS (cisco-sa-20180606-asaftd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Adaptive Security
Appliance (ASA) software running on the remote device is affected by
multiple vulnerabilities. Please see the included Cisco BIDs and Cisco
Security Advisories for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c235f451");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20180606-asaftd.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0296");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# The advisory notes multiple config options that could lead to a vulnerable case
# They seem to conflict/be inconsistent, so keeping this paranoid for now
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  model !~ '^411[0-9]($|[^0-9])'     && # Firepower 4110 SA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model !~ '^1000V'                  && # 1000V
  model != 'v' # ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCvi16029';

if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7.29)";
else if (version =~ "^9\.0[^0-9]")
  fixed_ver = "9.1(7.29)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.29)"))
  fixed_ver = "9.1(7.29)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.33)"))
  fixed_ver = "9.2(4.33)";
else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(4.18)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(4.18)"))
  fixed_ver = "9.4(4.18)";
else if (version =~ "^9\.5[^0-9]")
  fixed_ver = "9.6(4.8)";
else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(4.8)"))
  fixed_ver = "9.6(4.8)";
else if (version =~ "^9\.7[^0-9]" && check_asa_release(version:version, patched:"9.7(1.29)"))
  fixed_ver = "9.7(1.29)";
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


