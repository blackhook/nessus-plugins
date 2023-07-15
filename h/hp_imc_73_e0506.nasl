#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102500);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-12487",
    "CVE-2017-12488",
    "CVE-2017-12489",
    "CVE-2017-12490",
    "CVE-2017-12491",
    "CVE-2017-12492",
    "CVE-2017-12493",
    "CVE-2017-12494",
    "CVE-2017-12495",
    "CVE-2017-12496",
    "CVE-2017-12497",
    "CVE-2017-12498",
    "CVE-2017-12499",
    "CVE-2017-12500",
    "CVE-2017-12501",
    "CVE-2017-12502",
    "CVE-2017-12503",
    "CVE-2017-12504",
    "CVE-2017-12505",
    "CVE-2017-12506",
    "CVE-2017-12507",
    "CVE-2017-12508",
    "CVE-2017-12509",
    "CVE-2017-12510",
    "CVE-2017-12511",
    "CVE-2017-12512",
    "CVE-2017-12513",
    "CVE-2017-12514",
    "CVE-2017-12515",
    "CVE-2017-12516",
    "CVE-2017-12517",
    "CVE-2017-12518",
    "CVE-2017-12519",
    "CVE-2017-12520",
    "CVE-2017-12521",
    "CVE-2017-12522",
    "CVE-2017-12523",
    "CVE-2017-12524",
    "CVE-2017-12525",
    "CVE-2017-12526",
    "CVE-2017-12527",
    "CVE-2017-12528",
    "CVE-2017-12529",
    "CVE-2017-12530",
    "CVE-2017-12531",
    "CVE-2017-12532",
    "CVE-2017-12533",
    "CVE-2017-12534",
    "CVE-2017-12535",
    "CVE-2017-12536",
    "CVE-2017-12537",
    "CVE-2017-12538",
    "CVE-2017-12539",
    "CVE-2017-12540",
    "CVE-2017-12541"
  );
  script_xref(name:"HP", value:"emr_na-hpesbhf03768en_us");
  script_xref(name:"HP", value:"HPESBHF03768");

  script_name(english:"H3C / HPE Intelligent Management Center PLAT < 7.3 E0506 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HPE Intelligent Management Center (iMC) PLAT installed
on the remote host is prior to 7.3 E0506. It is, therefore, affected
by multiple vulnerabilities that can be exploited to execute arbitrary
code.

Note that Intelligent Management Center (iMC) is an HPE product;
however, it is branded as H3C.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03768en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8768af0a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to H3C / HPE iMC version 7.3 E0506 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12541");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_imc_detect.nbin");
  script_require_ports("Services/activemq", 61616);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Figure out which port to use
port = get_service(svc:'activemq', default:61616, exit_on_fail:TRUE);
version = get_kb_item_or_exit('hp/hp_imc/'+port+'/version');

app = 'HP Intelligent Management Center';

fixed_display = '7.3-E0506';

fix = NULL;
patchfix = NULL;

if (version =~ "^[0-6](\.[0-9]+)*$" || # e.g. 5, 6.999
    version =~ "^7\.0([0-9]|\.[0-9]+)*$" || # e.g. 7.01, 7.0.2
    version =~ "^7(\.[0-2])?$" # e.g. 7, 7.1, 7.2
)
{
  fix = "7.3";
}

# check patch version if 7.3
else if (version =~ "^7.3\-")
{
  # Versions < 7.3 E0506, remove letters and dashes in version
  patch = pregmatch(pattern:"[0-9.]+-E([0-9A-Z]+)", string:version);
  if (!patch) audit(AUDIT_UNKNOWN_APP_VER, app);
  patchver = ereg_replace(string:patch[1], pattern:"[A-Z\-]", replace:".");
  if (!patchver) audit(AUDIT_UNKNOWN_APP_VER, app);

  patchfix = "0506";
}

# if pre 7.3 or 7.3 with patchver before 0506
if ((!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0) ||
    (!isnull(patchfix) && ver_compare(ver:patchver, fix:patchfix, strict:FALSE) < 0))
{
  items = make_array(
    "Installed version", version,
    "Fixed version", fixed_display
  );

  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, version);
