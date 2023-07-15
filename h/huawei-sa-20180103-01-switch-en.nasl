#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117394);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  

  script_name(english:"Huawei Denial-of-Service Vulnerability");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial-of-service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Huawei product is affected by a denial-of-service
vulnerability.
");

  # https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180103-01-switch-en
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ce4f543");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate firmware patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:versatile_routing_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("huawei_vrp_version.nbin");
  script_require_keys("Host/Huawei/VRP/Series", "Host/Huawei/VRP/Version", "Host/Huawei/VRP/Model", "Settings/ParanoidReport");

  exit(0);
}

include("huawei_version.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

patchlist = get_kb_item_or_exit("Host/Huawei/VRP/display_patch-information");
model = get_kb_item_or_exit("Host/Huawei/VRP/Model");
series = get_kb_item_or_exit("Host/Huawei/VRP/Series");
version = get_kb_item_or_exit("Host/Huawei/VRP/Version");

reference = make_nested_list(
    make_array(
      "series", make_list("^S7700$"),
      "checks", make_nested_list(
        make_array("vuln", "V100R006C00", "fix", "Upgrade to version V2R10C00"),
        make_array("vuln", "V200R001C00", "fix", "Upgrade to version V2R10C00"),
        make_array("vuln", "V200R002C00", "fix", "Upgrade to version V2R10C00")
      )
    ),
    make_array(
      "series", make_list("^S9700$"),
      "checks", make_nested_list(
        make_array("vuln", "V200R001C00", "fix", "Upgrade to version V2R10C00")
      )
    )
);

huawei_check_and_report(
  model:model,
  series:series,
  version:version,
  reference:reference,
  patchlist:patchlist,
  severity:SECURITY_WARNING
);
