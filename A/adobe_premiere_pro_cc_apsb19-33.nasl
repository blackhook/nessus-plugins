#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134218);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/22");

  script_cve_id("CVE-2019-7931");

  script_name(english:"Adobe Premiere Pro CC < 13.1.3 Remote Code Execution (APSB19-33)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Pro CC installed on the remote Windows
host is prior to 13.1.3. It is, therefore, affected by a vulnerability
as referenced in the apsb19-33 advisory:

  - Insecure Library Loading (DLL hijacking) potentially leading
    to arbitrary code execution (CVE-2019-7931)

Note that Nessus has not attempted to exploit these issues but has instead relied
only on the application's self-reported version number.");
  # https://helpx.adobe.com/security/products/premiere_pro/apsb19-33.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13ea394d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Premiere Pro CC version 13.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_pro_installed.nasl");
  script_require_keys("installed_sw/Adobe Premiere Pro", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Premiere Pro', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '13.1.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
