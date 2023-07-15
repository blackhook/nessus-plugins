##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141854);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/23");

  script_cve_id("CVE-2020-24420");
  script_xref(name:"IAVA", value:"2020-A-0491-S");

  script_name(english:"Adobe Photoshop CC 20.x / 21.x < 21.2.3 Uncontrolled Search Path Element (APSB20-63)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop or Adobe Photoshop CC installed on the remote Windows host is prior to 21.2.3 (2020.2.3). It is,
therefore, affected by a vulnerability as referenced in the apsb20-63 advisory. Note that Nessus has not tested for this
issue but has instead relied only on the application's self-reported version number.");
  # https://helpx.adobe.com/security/products/photoshop/apsb20-63.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10922fd7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop/Photoshop CC version 21.2.3 or 22.0 later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24420");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_2020");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Photoshop', win_local:TRUE);

# Adobe Photoshop and Adobe Photoshop CC have different constraints
if ('CC' >< app_info.Product)
  constraints = [{ 'min_version' : '20', 'fixed_version' : '20.0.11', 'fixed_display' : '21.2.3 or 22.0' }];
else
  constraints = [{ 'min_version' : '21', 'fixed_version' : '21.2.3', 'fixed_display' : '21.2.3 or 22.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
