#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139602);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-9724");
  script_xref(name:"IAVA", value:"2020-A-0372-S");

  script_name(english:"Adobe Lightroom Classic <= 9.2.0.10 Privilege Escalation (APSB20-51)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Lightroom Classic installed on the remote Windows host is prior or equal to 9.2.0.10. It is, 
therefore, affected by an insecure library loading vulnerability. Successful exploitation could lead to a privilege
escalation.");
  # https://helpx.adobe.com/security/products/lightroom/apsb20-51.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?358fb50c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Lightroom Classic 9.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9724");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:lightroom");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_lightroom_classic_installed.nbin");
  script_require_keys("installed_sw/Adobe Lightroom Classic");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Lightroom Classic', win_local:TRUE);

constraints = [{ 'max_version' : '9.2.0.10', 'fixed_version' : '9.3' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


