#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128533);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id("CVE-2019-12627");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo29989");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190821-frpwr-td-info");
  script_xref(name:"IAVA", value:"2019-A-0314-S");

  script_name(english:"Cisco Firepower Threat Defense Software Information Disclosure Vulnerability");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense Software.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability
in the application policy configuration of the Cisco Firepower Threat Defense (FTD) Software, which
could allow an unauthenticated, remote attacker to gain unauthorized read access to sensitive data.
The vulnerability is due to insufficient application identification. An attacker could exploit this
vulnerability by sending crafted traffic to an affected device. A successful exploit could allow the
attacker to gain unauthorized read access to sensitive data.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190821-frpwr-td-info
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a964af89");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo29989");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo29989");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12627");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/show_ver", "Settings/ParanoidReport");

  exit(0);
}
include('audit.inc');
include('misc_func.inc');
include('global_settings.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
app = 'Cisco Firepower Threat Defense';
ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(ver)) audit(AUDIT_HOST_NOT, app);
ver = ver[1];
fix = '6.4.0.4';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) != -1) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

report =
  '\n  Bug               : CSCvn77248' +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix;
security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
