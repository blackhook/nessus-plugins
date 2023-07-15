##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142717);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2020-17067");

  script_name(english:"Security Updates for Microsoft Office Products (November 2020) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is affected by a Security Bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"Microsoft Office on MacOS is affected by a Security Bypass vulnerability.");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17ce16bb");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17067");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("installed_sw/Excel", "Host/MacOSX/Version");

  exit(0);
}

get_kb_item_or_exit('Host/MacOSX/Version');

include('vcf.inc');

app_info = vcf::get_app_info(app:'Microsoft Excel');

constraints = [
  { 'min_version' : '16.17.0', 'fixed_version' : '16.43', 'fixed_display' : '16.43 (20110804)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);