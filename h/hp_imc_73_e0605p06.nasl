#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119501);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-7114", "CVE-2018-7115", "CVE-2018-7116");
  script_xref(name:"TRA", value:"TRA-2018-28");

  script_name(english:"H3C / HPE Intelligent Management Center PLAT < 7.3 E0605P06 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A network management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HPE Intelligent Management Center (iMC) PLAT installed
on the remote host is prior to 7.3 E0605P06. It is, therefore,
affected by multiple vulnerabilities :

  - A stack-based buffer overflow condition exists in the dbman
    process due to improper validation of the length of user-supplied
    data when decrypting a request message. An unauthenticated,
    remote attacker can exploit this, via a specially crafted
    request, to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2018-7114)

  - A stack-based buffer overflow condition exists in the dbman
    process due to improper validation of the length of user-supplied
    data when writing the data to a debug log. An unauthenticated,
    remote attacker can exploit this, via a specially crafted
    request, to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2018-7115)

  - A denial of service (DoS) vulnerability exists in the dbman
    process due to improper validation of the length of user-supplied
    data when processing an AsnPlatManualRestoreReqContent ASN.1
    message. An unauthenticated, remote attacker can exploit this,
    via a specially crafted request, to cause the process to
    terminate and restart. (CVE-2018-7116)

Note that Intelligent Management Center (iMC) is an HPE product;
however, it is branded as H3C.");
  # https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03906en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?633d9824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to H3C / HPE iMC version 7.3 E0605P06 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_imc_detect.nbin");
  script_require_ports("Services/activemq", 61616);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get version
port = get_service(svc:"activemq", default:61616, exit_on_fail:TRUE);
version = get_kb_item_or_exit("hp/hp_imc/"+port+"/version");

app = "HP Intelligent Management Center";

fix_cmp = "7.3.0605.06";
fix     = "7.3-E0605P06";

# Check version format
match = pregmatch(pattern:"([0-9.]+)-E([0-9A-Z]+)", string:version);
if (empty_or_null(match)) audit(AUDIT_UNKNOWN_APP_VER, app);
release = match[1];

# Convert version: 7.3-E0102P03 -> 7.3.0101.03
patch = ereg_replace(string:match[2], pattern:"[A-Z]", replace:".");
if (!patch) audit(AUDIT_UNKNOWN_APP_VER, app);
ver = release + "." + patch;

# Compare version
if ((ver_compare(ver:ver, fix:fix_cmp, strict:FALSE) < 0))
{
  items = make_array(
    "Installed version", version,
    "Fixed version", fix
  );

  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, version);
