#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111107);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-6247",
    "CVE-2018-6248",
    "CVE-2018-6249",
    "CVE-2018-6250",
    "CVE-2018-6251",
    "CVE-2018-6252",
    "CVE-2018-6253"
  );

  script_name(english:"NVIDIA Linux GPU Display Driver Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing
a security update. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4649");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6251");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

kb_base = 'WMI/DisplayDrivers/';

# double check in case optimization is disabled
kbs = get_kb_list(kb_base + '*/Name');
if (isnull(kbs)) exit(0, 'No display drivers were found.');

report = '';

foreach kb (keys(kbs))
{
  name = kbs[kb];
  # only check NVIDIA drivers
  if ("NVIDIA" >!< name) continue;

  nvidia_found = TRUE;
  id = kb - kb_base - '/Name';
  version = get_kb_item_or_exit(kb_base + id + '/Version');
  driver_date = get_kb_item_or_exit(kb_base + id + '/DriverDate');

  disp_driver_date = driver_date;

  # convert to something we can pass to ver_compare (YYYY.MM.DD)
  driver_date = split(driver_date, sep:'/', keep:FALSE);
  driver_date = driver_date[2] + '.' + driver_date[0] + '.' + driver_date[1];
  fix = NULL;
  if (version =~ "^38(4|5|6)\." && ver_compare(ver:version, fix:"386.28", strict:FALSE) == -1) fix = "386.28";
  else if (version =~ "^39(0|1)\." && ver_compare(ver:version, fix:"391.29", strict:FALSE) == -1) fix = "391.29";
  
  if(!isnull(fix))
  {
    order = make_list('Device name','Driver version','Driver date','Fixed version');
    report = make_array(
      order[0],name,
      order[1],version,
      order[2],disp_driver_date,
      order[3],fix
      );

    report = report_items_str(report_items:report, ordered_fields:order);
    security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
    exit(0);
  }
  else
  {
    exit(0, "No vulnerable NVIDIA display drivers were found.");
  }
}

exit(0, 'No NVIDIA display drivers were found.');
