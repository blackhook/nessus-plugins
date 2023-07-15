#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140658);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/21");

  script_cve_id("CVE-2020-7268");
  script_xref(name:"MCAFEE-SB", value:"SB10329");
  script_xref(name:"IAVA", value:"2020-A-0426");

  script_name(english:"McAfee Email Gateway Web Mail User Interface Directory Traversal (SB10329)");

  script_set_attribute(attribute:"synopsis", value:
"An email proxy server running on the remote host is affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The McAfee Email Gateway (MEG) application running on the remote host is affected by a directory traversal
vulnerability in the Web Mail user interface. An authenticated, remote attacker can exploit this issue to traverse the
file system to access files or directories that are outside of the restricted directory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10329");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7268");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:email_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_email_gateway_version.nbin");
  script_require_keys("Host/McAfeeSMG/name", "Host/McAfeeSMG/version", "Host/McAfeeSMG/patches", "Settings/ParanoidReport");

  exit(0);
}
// only vuln if Web Mail enabled
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app_name = get_kb_item_or_exit('Host/McAfeeSMG/name');
version = get_kb_item_or_exit('Host/McAfeeSMG/version');
patches = get_kb_item_or_exit('Host/McAfeeSMG/patches');

# if not 7.6.x, not affected
if (version !~ "^7\.6")
  audit(AUDIT_INST_VER_NOT_VULN, version);

# fix version comes from patch/hotfix version/build
# e.g. MEG-7.6.404h1128596-3334.102.zip
fix = '7.6.3402.103';
hotfix = '7.6.406h1264651-3402.103';

# if version > fix, not affected
if (ver_compare(ver:version, fix:fix, strict:FALSE) > 0)
  audit(AUDIT_INST_VER_NOT_VULN, version);

# if patch installed, not affected
if ('h1264651' >< patches && '7.6.406' >< patches)
  audit(AUDIT_PATCH_INSTALLED, hotfix, app_name, version);

# report
port = 0;
report = '\n' + app_name + ' ' + version + ' is missing hotfix ' + hotfix + '.\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);

