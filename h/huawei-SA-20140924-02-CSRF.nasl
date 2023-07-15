#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80087);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_bugtraq_id(70114);

  script_name(english:"Multiple XSRF Vulnerabilities in Huawei Products (HWPSIRT-2014-0406)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site request forgery
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Huawei device is running a firmware version that is
affected by multiple cross-site request forgery vulnerabilities in the
web interface.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-372186.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de58c16b");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("huawei_vsp_version.nbin");
  script_require_keys("Settings/ParanoidReport", "Host/Huawei/VSP/Series", "Host/Huawei/VSP/Version", "Host/Huawei/VSP/Model");

  exit(0);
}

include("huawei_version.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item_or_exit("Host/Huawei/VSP/Model");
series = get_kb_item_or_exit("Host/Huawei/VSP/Series");
version = get_kb_item_or_exit("Host/Huawei/VSP/Version");

reference = make_nested_list(
  make_array(
    "series", make_list("^USG9500$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R001C01SPC800", "fix", "V200R001C01SPC900"),
      make_array("vuln", "V300R001C00", "fix", "V300R001C01SPC300")
      )
    ),
  make_array(
    "series", make_list("^USG2100$", "^USG2200$", "^USG5100$", "^USG5500$"),
    "checks", make_nested_list(
      make_array("vuln", "V300R001C00SPC900", "fix", "V300R001C10SPC200 / V300R001C10SPC200SPH201")
      )
    )
  );

huawei_check_and_report(
  model:model,
  series:series,
  version:version,
  reference:reference,
  severity:SECURITY_WARNING,
  xsrf:TRUE
);
