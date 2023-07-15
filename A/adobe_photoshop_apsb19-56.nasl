#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132022);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/20");

  script_cve_id("CVE-2019-8253", "CVE-2019-8254");

  script_name(english:"Adobe Photoshop CC 20.x <= 20.0.7 / 21.x <= 21.0.1 Multiple Vulnerabilities (APSB19-56)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC installed on the remote Windows host is prior to 20.0.8 (2019.0.8), 21.0.2 (2020.0.2).
It is, therefore, affected by multiple unspecified memory corruption vulnerabilities exist. An attacker can exploit this
to execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb19-56.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC version 20.0.8 (2019.0.8), 21.0.2 (2020.0.2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Photoshop', win_local:TRUE);

if ('CC' >!< app_info.Product) vcf::vcf_exit(0, 'Only Adobe Photoshop CC is affected.');

constraints = [
  { 'min_version' : '20', 'max_version' : '20.0.7', 'fixed_version' : '20.0.8' },
  { 'min_version' : '21', 'max_version' : '21.0.1', 'fixed_version' : '21.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
