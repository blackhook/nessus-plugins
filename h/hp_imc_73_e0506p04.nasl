#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103788);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-8958",
    "CVE-2017-8961",
    "CVE-2017-8962",
    "CVE-2017-8963",
    "CVE-2017-8964",
    "CVE-2017-8965",
    "CVE-2017-8966",
    "CVE-2017-8967"
  );
  script_bugtraq_id(101202);
  script_xref(name:"HP", value:"emr_na-hpesbhf03786en_us");
  script_xref(name:"HP", value:"HPESBHF03786");
  script_xref(name:"HP", value:"emr_na-hpesbhf03787en_us");
  script_xref(name:"HP", value:"HPESBHF03787");
  script_xref(name:"HP", value:"emr_na-hpesbhf03788en_us");
  script_xref(name:"HP", value:"HPESBHF03788");

  script_name(english:"H3C / HPE Intelligent Management Center PLAT < 7.3 E0506P03 Multiple RCE");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HPE Intelligent Management Center (iMC) PLAT installed
on the remote host is prior to 7.3 E0506P03. It is, therefore,
affected by multiple remote code execution vulnerabilities.

Note that Intelligent Management Center (iMC) is an HPE product;
however, it is branded as H3C.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03786en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?921e68d0");
  # https://support.hpe.com/hpsc/doc/public/display?docId=hpesbhf03787en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76d7a548");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03788en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da943b3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to H3C / HPE iMC version 7.3 E0506P03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

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

fixed_display = '7.3-E0506P03';

fix = "7.3";
patchfix = NULL;

# check patch version if 7.3
if (version =~ "^7.[0-3]\-")
{
  # Versions < 7.3 E0506, remove letters and dashes in version
  patch = pregmatch(pattern:"[0-9.]+-E([0-9A-Z]+)", string:version);
  if (!patch) audit(AUDIT_UNKNOWN_APP_VER, app);
  patchver = ereg_replace(string:patch[1], pattern:"[A-Z\-]", replace:".");
  if (!patchver) audit(AUDIT_UNKNOWN_APP_VER, app);

  patchfix = "0506.03";
}

# if pre 7.3 or 7.3 with patchver before 0506
if ((ver_compare(ver:version, fix:fix, strict:FALSE) < 0) ||
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
