#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103050);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_bugtraq_id(54068);

  script_name(english:"Western Digital TV Multiple Vulnerabilities");
  script_summary(english:"Checks the firmware version of the WD TV device");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote WD TV device is affected by multiple vulnerabilities
including arbitrary file upload, local file inclusion, and SQL injection.");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20170518-0_WDTV_Media_Player_Multiple_critical_vulnerabilities_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?794b221d");
  # http://blog.dixo.net/2012/12/hacking-the-wdtv-live-streaming-media-player/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d67ee427");
  script_set_attribute(attribute:"solution", value:
"No patches exist for these vulnerabilities and it appears that
Western Digital is no longer maintaining these devices.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
    script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("wd_tv_www_detect.nbin");
  script_require_keys("installed_sw/WD TV");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");

get_install_count(app_name:"WD TV", exit_if_zero:TRUE);
var port = get_http_port(default:80, embedded:TRUE);
var install = get_single_install(app_name:"WD TV", port:port);

if (isnull(install["version"])) audit(AUDIT_UNKNOWN_DEVICE_VER, "a WD TV device");

# These vulnerabilities apply to multiple WD TV devices because
# they all share a common code base. However, they have different
# firmware versioning. There is no real way for an unauthenticated
# user to determine the device type except by mapping the
# firmware version to a device.

var firmware_table = make_array();
# https://support.wdc.com/download/notes/WDTV_Live_Hub_Release_Notes_3_12_13.pdf?v=298
firmware_table["3.12.13"] = "WD TV Live Hub Media Center";
firmware_table["3.11.10"] = "WD TV Live Hub Media Center";
firmware_table["3.10.09"] = "WD TV Live Hub Media Center";
firmware_table["3.09.18"] = "WD TV Live Hub Media Center";
firmware_table["3.08.14"] = "WD TV Live Hub Media Center";
firmware_table["3.07.14"] = "WD TV Live Hub Media Center";
firmware_table["3.06.14"] = "WD TV Live Hub Media Center";
firmware_table["3.05.10"] = "WD TV Live Hub Media Center";
firmware_table["3.04.17"] = "WD TV Live Hub Media Center";
firmware_table["3.03.16"] = "WD TV Live Hub Media Center";
firmware_table["3.03.13"] = "WD TV Live Hub Media Center";
firmware_table["3.01.19"] = "WD TV Live Hub Media Center";
firmware_table["3.00.28"] = "WD TV Live Hub Media Center";
firmware_table["2.08.13"] = "WD TV Live Hub Media Center";
firmware_table["2.07.17"] = "WD TV Live Hub Media Center";
firmware_table["2.06.10"] = "WD TV Live Hub Media Center";
firmware_table["2.05.08"] = "WD TV Live Hub Media Center";
firmware_table["2.04.13"] = "WD TV Live Hub Media Center";
firmware_table["2.03.24"] = "WD TV Live Hub Media Center";
firmware_table["2.02.19"] = "WD TV Live Hub Media Center";
firmware_table["2.02.16"] = "WD TV Live Hub Media Center";

# https://support.wdc.com/download/notes/WDTV_Live_Streaming_FW_Release_Notes_2_03_20.pdf?v=679
firmware_table["2.03.20"] = "WD TV Live Streaming Media Player";
firmware_table["2.02.32"] = "WD TV Live Streaming Media Player";
firmware_table["2.01.86"] = "WD TV Live Streaming Media Player";
firmware_table["1.16.13"] = "WD TV Live Streaming Media Player";
firmware_table["1.15.10"] = "WD TV Live Streaming Media Player";
firmware_table["1.14.09"] = "WD TV Live Streaming Media Player";
firmware_table["1.13.18"] = "WD TV Live Streaming Media Player";
firmware_table["1.12.14"] = "WD TV Live Streaming Media Player";
firmware_table["1.11.14"] = "WD TV Live Streaming Media Player";
firmware_table["1.10.13"] = "WD TV Live Streaming Media Player";
firmware_table["1.09.10"] = "WD TV Live Streaming Media Player";
firmware_table["1.08.17"] = "WD TV Live Streaming Media Player";
firmware_table["1.07.18"] = "WD TV Live Streaming Media Player";
firmware_table["1.07.15"] = "WD TV Live Streaming Media Player";
firmware_table["1.06.04"] = "WD TV Live Streaming Media Player";
firmware_table["1.05.18"] = "WD TV Live Streaming Media Player";
firmware_table["1.04.12"] = "WD TV Live Streaming Media Player";
firmware_table["1.03.10"] = "WD TV Live Streaming Media Player";

# https://support.wdc.com/download/notes/WDTV_Firmware_Release_Notes_1_03_07.pdf?v=904
firmware_table["1.03.07"] = "WD TV Media Player";
firmware_table["1.02.17"] = "WD TV Media Player";
firmware_table["1.01.30"] = "WD TV Media Player";

if (!isnull(firmware_table[install["version"]]))
{
  var report =
    '\n' + "URL: " + build_url(qs:'/', port:port) +
    '\n' + "Device type: " + firmware_table[install["version"]] +
    '\n' + "Firmware version: " + install["version"] +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, sqli:TRUE);
  exit(0);
}

audit(AUDIT_HOST_NOT, "an affected WD TV device");
