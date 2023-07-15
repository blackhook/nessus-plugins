#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(101810);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/22");

  script_cve_id("CVE-2017-9765");
  script_bugtraq_id(99868);

  script_name(english:"AXIS gSOAP Message Handling RCE (ACV-116267) (Devil's Ivy)");
  script_summary(english:"Checks the version of the AXIS device.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote AXIS device is running a firmware version that is missing a
security patch. It is, therefore, affected by a remote code execution
vulnerability, known as Devil's Ivy, due to an overflow condition that
exists in a third party SOAP library (gSOAP). An unauthenticated,
remote attacker can exploit this, via an HTTP POST message exceeding
2GB of data, to trigger a stack-based buffer overflow, resulting in a
denial of service condition or the execution of arbitrary code.

An attacker who successfully exploits this vulnerability can reset the
device to its factory defaults, change network settings, take complete
control of the device, or reboot it to prevent an operator from
viewing the feed.");
  script_set_attribute(attribute:"see_also", value:"https://www.axis.com/files/faq/ACV116267_(CVE-2017-9765).pdf");
  script_set_attribute(attribute:"see_also", value:"https://www.axis.com/ftp/pub_soft/MPQT/SR/acv_116267_patched_fw.txt");
  script_set_attribute(attribute:"see_also", value:"http://blog.senr.io/devilsivy.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest available firmware version for your device per
the vendor advisory (ACV-116267).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9765");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:genivia:gsoap");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("snmp_sysDesc.nasl", "ftpserver_detect_type_nd_version.nasl", "axis_www_detect.nbin");
  script_require_ports("SNMP/sysDesc", "Services/ftp", "Services/www", 21, 80);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('ftp_func.inc');
include('misc_func.inc');
include('http.inc');
include('install_func.inc');

patch_list = {
  "A1001" :{"1\.(?:[0-4][0-9]|50)\.":"1.50.0.2", "1\.5[1-7]\.":"1.57.0.2"},
  "A8004" : "1.65.1",
  "A8105-E" : "1.58.2.2",
  "A9161" : "1.10.0.2",
  "A9188" : "1.10.0.2",
  "A9188-VE" : "1.10.0.2",
  "C1004-E" : "1.30.0.2",
  "C2005" : "1.30.0.2",
  "C3003" : "1.30.0.2",
  "ACB-LE" : "6.15.5.3",
  "ACC-L" : "6.15.6.3",
  "ACC-LW" : "6.15.6.3",
  "ACD-V" : "6.15.6.3",
  "ACD-WV" : "6.15.6.3",
  "ACE-L" : "6.15.5.3",
  "F34" : "6.50.1.2",
  "F41" : "6.50.1.2",
  "F44" : "6.50.1.2",
  "F44DualAudioInput" : "6.50.1.2",
  "M1004-W" : "5.50.5.10",
  "M1011" : "5.20.3",
  "M1011-W" : "5.20.4",
  "M1013" : "5.50.5.10",
  "M1014" : "5.50.5.10",
  "M1025" : "5.50.5.10",
  "M1031-W" : "5.20.5",
  "M1033-W" : "5.50.5.10",
  "M1034-W" : "5.50.5.10",
  "M1045-LW" : "6.15.6.1",
  "M1054" : "5.50.3.10",
  "M1065-L" : "7.20.1",
  "M1065-LW" : "6.15.6.1",
  "M1103" : "5.50.3.6",
  "M1104" : "5.50.3.6",
  "M1113" : "5.50.3.6",
  "M1114" : "5.50.3.6",
  "M1124" : "6.50.1.2",
  "M1125" : "6.50.1.2",
  "M1143-L" : "5.60.1.8",
  "M1144-L" : "5.60.1.8",
  "M1145" : "6.50.1.2",
  "M1145-L" : "6.50.1.2",
  "M2025-LE" : "7.20.1",
  "M2026-LE" : "7.20.1",
  "M3004" : "5.50.5.10",
  "M3005" : "5.50.5.10",
  "M3006" : "6.50.1.2",
  "M3007" : "6.50.1.2",
  "M3011" : "5.21.2",
  "M3014" : {"5\.(?:[0-3][0-9]|40)\.":"5.40.9.9", "5\.(?:4[1-9]|50)\.":"5.50.5.2"},
  "M3024" : "5.50.5.10",
  "M3025" : "5.50.5.10",
  "M3026" : "6.50.1.2",
  "M3027" : "6.50.1.2",
  "M3037" : "5.75.1.3",
  "M3044-V" : "7.20.1",
  "M3044-WV" : "6.15.6.1",
  "M3045-V" : "7.20.1",
  "M3045-WV" : "6.15.6.1",
  "M3046-V_1.8mm" : "6.15.7.1",
  "M3046-V" : "7.20.1",
  "M3104-L" : "7.20.1",
  "M3105-L" : "7.20.1",
  "M3106-L" : "7.20.1",
  "M3113-R" : "5.40.9.9",
  "M3113-VE" : "5.40.9.9",
  "M3114-R" : "5.40.9.9",
  "M3114-VE" : "5.40.9.9",
  "P8513" : "5.40.9.9",
  "P8514" : "5.40.9.9",
  "M3113-R" : "5.50.5.1",
  "M3113-VE" : "5.50.5.1",
  "M3114-R" : "5.50.5.1",
  "M3114-VE" : "5.50.5.1",
  "P8513" : "5.50.5.1",
  "P8514" : "5.50.5.1",
  "M3203" : "5.50.3.7",
  "M3204" : "5.50.3.7",
  "M5013" : "5.50.3.7",
  "M5014" : "5.50.3.7",
  "M7001" : "5.20.5",
  "M7011" : "6.50.1.2",
  "M7010" : "5.50.4.7",
  "M7014" : "5.50.4.7",
  "M7016" : "5.51.2.8",
  "M2014-E" : "5.50.9.2",
  "P1204" : "5.50.9.2",
  "P1214" : "5.50.9.2",
  "P1214-E" : "5.50.9.2",
  "P1224-E" : "5.50.9.2",
  "P12/M20" : "5.50.9.2",
  "P8524" : "5.50.9.2",
  "P1244" : "6.50.1.2",
  "P1254" : "6.50.1.2",
  "P1264" : "6.50.1.2",
  "P1311" : "5.20.2",
  "P1343" : {"5\.(?:[0-3][0-9]|40)\.":"5.40.9.11", "5\.(?:4[1-9]|50)\.":"5.50.5.1"},
  "P1344" : {"5\.(?:[0-3][0-9]|40)\.":"5.40.9.11", "5\.(?:4[1-9]|50)\.":"5.50.5.1"},
  "P1346" : "5.40.9.9",
  "P1347" : "5.40.9.9",
  "P1353" : "6.50.1.2",
  "P1354" : "6.50.1.2",
  "P1355" : "5.60.1.8",
  "P1357" : "6.50.1.2",
  "P1364" : {"7\.[0-2][0-9]\.":"7.20.1", "(?:6\.[0-5][0-9]|5\.85)\.":"6.50.1.2"},
  "P1365" : "6.50.1.2",
  "P1365 Mk II" : {"7\.[0-2][0-9]\.":"7.20.1", "(?:6\.[0-5][0-9]|5\.85)\.":"6.50.1.2"},
  "P1405" : "6.50.1.2",
  "P1405-LE Mk II" : "7.20.1",
  "P1425" : "6.50.1.2",
  "P1425-LE Mk II" : "7.20.1",
  "P1427" : "6.50.1.2",
  "P1428-E" : "6.50.1.2",
  "P1435" : {"7\.[0-2][0-9]\.":"7.20.1", "(?:6\.[0-5][0-9]|5\.85)\.":"6.50.1.2"},
  "P3214" : "6.50.1.2",
  "P3215" : "6.50.1.2",
  "P3224" : "6.50.1.2",
  "P3225" : "6.50.1.2",
  "P3224-V Mk II" : "6.55.5",
  "P3224-VE Mk II" : "6.55.5",
  "P3224-LV Mk II" : "6.55.5",
  "P3224-LVE Mk II" : "6.55.5",
  "P3225-V Mk II" : "6.55.5",
  "P3225-VE Mk II" : "6.55.5",
  "P3225-LV Mk II" : "6.55.5",
  "P3225-LVE Mk II" : "6.55.5",
  "P3301" : {"5\.(?:[0-3][0-9]|40)\.":"5.40.9.7", "5\.(?:4[1-9]|50)\.":"5.50.5.1"},
  "P3304" : {"5\.(?:[0-3][0-9]|40)\.":"5.40.9.7", "5\.(?:4[1-9]|50)\.":"5.50.5.1"},
  "P3343" : "5.40.9.11",
  "P3344" : "5.40.9.11",
  "P3346" : "5.50.3.7",
  "P3353" : {"6\.[0-5][0-9]\.":"6.50.1.2", "5\.(?:4[1-9]|[5-6][0-9])\.":"5.60.1.5", "5\.(?:[0-3][0-9]|40)\.":"5.40.17.2"},
  "P3354" : {"6\.[0-5][0-9]\.":"6.50.1.2", "5\.(?:4[1-9]|[5-6][0-9])\.":"5.60.1.5", "5\.(?:[0-3][0-9]|40)\.":"5.40.17.2"},
  "P3363" : {"6\.[0-5][0-9]\.":"6.50.1.2", "5\.[0-6][0-9]\.":"5.60.1.7"},
  "P3364" : {"6\.[0-5][0-9]\.":"6.50.1.2", "5\.(?:4[1-9]|[5-6][0-9])\.":"5.60.1.7", "5\.(?:[0-3][0-9]|40)\.":"5.40.17.2"},
  "P3365" : "6.50.1.2",
  "P3367" : "6.50.1.2",
  "P3384" : "6.50.1.2",
  "P3707-PE" : "6.50.1.3",
  "P3904" : "6.50.1.2",
  "P3904-R" : "6.50.1.2",
  "P3905" : "6.50.1.2",
  "P3915-R" : "6.50.1.2",
  "P5414-E" : "6.50.1.2",
  "P5415-E" : "6.50.1.2",
  "P5512" : "5.50.4.7",
  "P5512-E" : "5.50.4.7",
  "P5514" : {"7\.[0-2][0-9]\.":"7.20.1", "(?:6\.[0-5][0-9]|5\.85)\.":"6.50.1.2"},
  "P5514-E" : {"7\.[0-2][0-9]\.":"7.20.1", "(?:6\.[0-5][0-9]|5\.85)\.":"6.50.1.2"},
  "P5515" : {"7\.[0-2][0-9]\.":"7.20.1", "(?:6\.[0-5][0-9]|5\.85)\.":"6.50.1.2"},
  "P5515-E" : {"7\.[0-2][0-9]\.":"7.20.1", "(?:6\.[0-5][0-9]|5\.85)\.":"6.50.1.2"},
  "P5522" : "5.50.4.8",
  "P5522-E" : "5.50.4.7",
  "P5532" : "5.41.3.4",
  "P5532-E" : "5.41.3.4",
  "P5534" : "5.40.9.8",
  "P5534-E" : "5.40.9.9",
  "P5544" : "5.41.2.4",
  "P5624-E" : "6.50.1.2",
  "P5624-E Mk II" : {"7\.[0-2][0-9]\.":"7.20.1", "6\.[0-5][0-9]\.":"6.50.1.2"},
  "P5635-E" : "6.50.1.2",
  "P5635-E Mk II" : {"7\.[0-2][0-9]\.":"7.20.1", "6\.[0-5][0-9]\.":"6.50.1.2"},
  "P7210" : "5.50.4.7",
  "P7214" : "5.50.4.7",
  "P7216" : "5.51.2.7",
  "P7224" : "5.51.2.7",
  "Q1602" : "5.60.1.8",
  "Q1604" : "6.50.1.2",
  "Q1614" : "6.50.1.2",
  "Q1615" : "6.50.1.2",
  "Q1635" : "6.50.1.2",
  "Q1635-E" : "6.50.1.2",
  "Q1615 Mk II" : "6.25.2.6",
  "Q1659" : "6.55.1.1",
  "Q1755" : "5.50.4.6",
  "Q1755-PT" : "5.50.2.2",
  "Q8722-E" : "5.50.2.2",
  "Q1765-EX" : "6.50.1.2",
  "Q1765-LE" : "6.50.1.2",
  "Q1765-LE-PT" : "6.50.1.2",
  "Q1775" : {"7\.[0-2][0-9]\.":"7.20.1", "(?:6\.[0-5][0-9]|5\.85)\.":"6.50.1.2"},
  "Q1910" : "5.50.4.6",
  "Q1921" : "5.50.4.6",
  "Q1922" : "5.50.4.6",
  "Q1931-E" : "6.50.1.2",
  "Q1931-E-PT" : "6.50.1.2",
  "Q1932-E" : "6.50.1.2",
  "Q1932-E-PT" : "6.50.1.2",
  "Q1941-E" : "7.20.1",
  "Q1942-E" : "7.20.1",
  "Q2901-E" : "6.50.1.2",
  "Q2901-E-PT" : "6.50.1.2",
  "Q3505" : "6.50.1.2",
  "Q3504" : "6.25.2.5",
  "Q3505 Mk II" : "6.25.2.5",
  "Q3615" : "7.20.1",
  "Q3617" : "7.20.1",
  "Q3708-PVE" : "5.95.4.4",
  "Q3709-PVE" : "5.75.1.6",
  "Q6000-E" : "6.50.1.2",
  "Q6000-E Mk II" : "6.50.1.2",
  "Q6032" : "5.41.1.5",
  "Q6032-C" : "5.41.3.2",
  "Q6032-E" : "5.41.1.7",
  "Q6034" : "5.41.1.4",
  "Q6034-C" : "5.41.3.2",
  "Q6034-E" : "5.41.1.6",
  "Q6035" : "5.41.1.5",
  "Q6035-C" : "5.41.3.3",
  "Q6035-E" : "5.41.1.8",
  "Q6042" : "6.50.1.2",
  "Q6042-C" : "6.50.1.2",
  "Q6042-E" : "6.50.1.2",
  "Q6042-S" : "6.50.1.2",
  "Q6044" : "6.50.1.2",
  "Q6044-C" : "6.50.1.2",
  "Q6044-E" : "6.50.1.2",
  "Q6044-S" : "6.50.1.2",
  "Q6045" : "5.70.1.4",
  "Q6045-C" : "5.70.1.3",
  "Q6045-C Mk II" : "6.50.1.2",
  "Q6045-E" : "5.70.1.5",
  "Q6045-E Mk II" : "6.50.1.2",
  "Q6045 Mk II" : "6.50.1.2",
  "Q6045-S" : "5.70.1.3",
  "Q6045-S Mk II" : "6.50.1.2",
  "Q6052" : {"7\.[0-2][0-9]\.":"7.20.1", "6\.[0-5][0-9]\.":"6.50.1.2"},
  "Q6052-E" : {"7\.[0-2][0-9]\.":"7.20.1", "6\.[0-5][0-9]\.":"6.50.1.2"},
  "Q6054" : {"7\.[0-2][0-9]\.":"7.20.1", "6\.[0-5][0-9]\.":"6.50.1.2"},
  "Q6054-E" : "7.20.1",
  "Q6054-E" : "6.50.1.2",
  "Q6055" : {"7\.[0-2][0-9]\.":"7.20.1", "6\.[0-5][0-9]\.":"6.50.1.2"},
  "Q6055-C" : "7.20.1",
  "Q6055-E" : {"7\.[0-2][0-9]\.":"7.20.1", "6\.[0-5][0-9]\.":"6.50.1.2"},
  "Q6055-S" : "7.20.1",
  "Q6114-E" : "6.50.1.2",
  "Q6115-E" : "6.50.1.2",
  "Q6128-E" : "6.50.1.2",
  "Q6155-E" : "7.20.1",
  "Q6155-E" : "6.50.1.2",
  "Q7401" : "5.50.4.6",
  "Q7404" : "5.50.4.7",
  "Q7406" : "5.51.2.6",
  "Q7411" : "6.50.1.2",
  "Q7414" : "5.51.2.6",
  "Q7424-R" : "5.50.4.6",
  "Q7424-R Mk II" : "5.51.3.2",
  "Q7436" : "6.50.1.2",
  "Q8414-LVS" : "6.50.1.2",
  "Q8631-E" : "6.50.1.2",
  "Q8632-E" : "6.50.1.2",
  "Q8665-E" : "6.50.1.2",
  "Q8665-LE" : "6.50.1.2",
  "ACR" : "1.11.1",
  "V5914" : "5.75.1.7",
  "V5915" : "5.75.1.7" 
};

model = '';
version = '';
source = '';

##
# This vulnerability is in the web interface. If our web interface
# is failing to extract the version / model for some reason than
# a paranoid check can fall back to FTP and SNMP.
#
# @return NULL
##
function do_paranoid()
{
  var ftp_port_list = get_kb_list("Services/ftp");
  if (empty_or_null(ftp_port_list))
  {
    # add default port (in case we have an empty list)
    ftp_port_list = add_port_in_list(port: 21);
  }

  var port = 0;
  foreach port (ftp_port_list)
  {
    var banner = get_ftp_banner(port:port);
    if (!banner) continue;

    # ftp banner parser
    var item = pregmatch(string:banner,
      pattern:"^220 (?:Axis|AXIS) ([0-9a-zA-Z-]+(?: Mk[ ]?II)?(?: Board [A-Z]+)?) [^0-9]+ ([0-9\\.]+)");

    if(!empty_or_null(item))
    {
      # fix inconsistent formatting
      model = str_replace(find:'MkII', replace:'Mk II', string:item[1]);
      source = "FTP";
      version = item[2];
      return NULL;
    }
  }

  var snmp_desc = get_kb_list("SNMP/sysDesc");
  if (!empty_or_null(snmp_desc))
  {
    var desc = NULL;
    foreach desc (snmp_desc)
    {
      item = pregmatch(pattern:"^\s*;\s*(?:AXIS|Axis) ([^;]+);[^;]+;\s*([\d.]+)[^\d.]", string:desc);
      if(!empty_or_null(item))
      {
        # fix inconsistent formatting
        model = str_replace(find:'MkII', replace:'Mk II', string:item[1]);
        version = item[2];
        source = "SNMP";
        return NULL;
      }
    }
  }

  return NULL;
}

# loop over the AXIS web installs and pull out the model/version
if (get_install_count(app_name:"AXIS device") > 0)
{
  http_port_list = get_kb_list("Services/www");
  if (empty_or_null(http_port_list))
  {
    http_port_list = add_port_in_list(port: 80);
  }

  foreach port (http_port_list)
  {
    installs = get_installs(app_name:'AXIS device', port:port, exit_if_not_found:FALSE);
    if (installs[0] != IF_OK)
    {
      continue;
    }

    install = installs[1][0];
    if (!empty_or_null(install["version"]) && !empty_or_null(install["model"]))
    {
      source = "HTTP";
      model = install["model"];
      version = install["version"];

      # fix inconsistent formatting
      model = str_replace(find:'MkII', replace:'Mk II', string:model);
      break;
    }
  }
}

# The vulnerability is through the web interface. However, if we are feeling
# paranoid we can lean on other protocols to inform us of the version
if (report_paranoia >= 2 && (empty_or_null(model) || empty_or_null(version)))
{
  do_paranoid();
}

if (empty_or_null(model) || empty_or_null(version))
{
  audit(AUDIT_HOST_NOT, "an AXIS device");
}

if(isnull(patch_list[model]))
{
  audit(AUDIT_DEVICE_NOT_VULN, "The AXIS " + model, version);
}

fix = NULL;

# some models have multiple fixed branches
if(typeof_ex(patch_list[model]) == "array")
{
  foreach branch (keys(patch_list[model]))
  {
    # add an anchor to ensure the match only occurs at the beginning
    if (preg(string:version, pattern:"^" + branch) == TRUE)
    {
      fix = patch_list[model][branch];

      # if we found it then don't keep looping
      break;
    }
  }

  if(isnull(fix))
  {
    audit(AUDIT_DEVICE_NOT_VULN, "The AXIS " + model, version);
  }
}
else
{
  fix = patch_list[model];
}

if (!empty_or_null(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report = '\n  Model            : ' + model +
           '\n  Software version : ' + version +
           '\n  Version source   : ' + source +
           '\n  Fixed version    : ' + fix + '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
  exit(0);
}

audit(AUDIT_DEVICE_NOT_VULN, "The AXIS " + model, version);
