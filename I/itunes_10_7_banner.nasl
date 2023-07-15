#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62078);
  script_version("1.16");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2011-3016",
    "CVE-2011-3021",
    "CVE-2011-3027",
    "CVE-2011-3032",
    "CVE-2011-3034",
    "CVE-2011-3035",
    "CVE-2011-3036",
    "CVE-2011-3037",
    "CVE-2011-3038",
    "CVE-2011-3039",
    "CVE-2011-3040",
    "CVE-2011-3041",
    "CVE-2011-3042",
    "CVE-2011-3043",
    "CVE-2011-3044",
    "CVE-2011-3050",
    "CVE-2011-3053",
    "CVE-2011-3059",
    "CVE-2011-3060",
    "CVE-2011-3064",
    "CVE-2011-3068",
    "CVE-2011-3069",
    "CVE-2011-3071",
    "CVE-2011-3073",
    "CVE-2011-3074",
    "CVE-2011-3075",
    "CVE-2011-3076",
    "CVE-2011-3078",
    "CVE-2011-3081",
    "CVE-2011-3086",
    "CVE-2011-3089",
    "CVE-2011-3090",
    "CVE-2011-3105",
    "CVE-2011-3913",
    "CVE-2011-3924",
    "CVE-2011-3926",
    "CVE-2011-3958",
    "CVE-2011-3966",
    "CVE-2011-3968",
    "CVE-2011-3969",
    "CVE-2011-3971",
    "CVE-2012-0682",
    "CVE-2012-0683",
    "CVE-2012-1520",
    "CVE-2012-1521",
    "CVE-2012-2817",
    "CVE-2012-2818",
    "CVE-2012-2829",
    "CVE-2012-2831",
    "CVE-2012-2842",
    "CVE-2012-2843",
    "CVE-2012-3589",
    "CVE-2012-3590",
    "CVE-2012-3591",
    "CVE-2012-3592",
    "CVE-2012-3593",
    "CVE-2012-3594",
    "CVE-2012-3595",
    "CVE-2012-3596",
    "CVE-2012-3597",
    "CVE-2012-3598",
    "CVE-2012-3599",
    "CVE-2012-3600",
    "CVE-2012-3601",
    "CVE-2012-3602",
    "CVE-2012-3603",
    "CVE-2012-3604",
    "CVE-2012-3605",
    "CVE-2012-3606",
    "CVE-2012-3607",
    "CVE-2012-3608",
    "CVE-2012-3609",
    "CVE-2012-3610",
    "CVE-2012-3611",
    "CVE-2012-3612",
    "CVE-2012-3613",
    "CVE-2012-3614",
    "CVE-2012-3615",
    "CVE-2012-3616",
    "CVE-2012-3617",
    "CVE-2012-3618",
    "CVE-2012-3620",
    "CVE-2012-3621",
    "CVE-2012-3622",
    "CVE-2012-3623",
    "CVE-2012-3624",
    "CVE-2012-3625",
    "CVE-2012-3626",
    "CVE-2012-3627",
    "CVE-2012-3628",
    "CVE-2012-3629",
    "CVE-2012-3630",
    "CVE-2012-3631",
    "CVE-2012-3632",
    "CVE-2012-3633",
    "CVE-2012-3634",
    "CVE-2012-3635",
    "CVE-2012-3636",
    "CVE-2012-3637",
    "CVE-2012-3638",
    "CVE-2012-3639",
    "CVE-2012-3640",
    "CVE-2012-3641",
    "CVE-2012-3642",
    "CVE-2012-3643",
    "CVE-2012-3644",
    "CVE-2012-3645",
    "CVE-2012-3646",
    "CVE-2012-3647",
    "CVE-2012-3648",
    "CVE-2012-3649",
    "CVE-2012-3651",
    "CVE-2012-3652",
    "CVE-2012-3653",
    "CVE-2012-3654",
    "CVE-2012-3655",
    "CVE-2012-3656",
    "CVE-2012-3657",
    "CVE-2012-3658",
    "CVE-2012-3659",
    "CVE-2012-3660",
    "CVE-2012-3661",
    "CVE-2012-3663",
    "CVE-2012-3664",
    "CVE-2012-3665",
    "CVE-2012-3666",
    "CVE-2012-3667",
    "CVE-2012-3668",
    "CVE-2012-3669",
    "CVE-2012-3670",
    "CVE-2012-3671",
    "CVE-2012-3672",
    "CVE-2012-3673",
    "CVE-2012-3674",
    "CVE-2012-3675",
    "CVE-2012-3676",
    "CVE-2012-3677",
    "CVE-2012-3678",
    "CVE-2012-3679",
    "CVE-2012-3680",
    "CVE-2012-3681",
    "CVE-2012-3682",
    "CVE-2012-3683",
    "CVE-2012-3684",
    "CVE-2012-3685",
    "CVE-2012-3686",
    "CVE-2012-3687",
    "CVE-2012-3688",
    "CVE-2012-3692",
    "CVE-2012-3699",
    "CVE-2012-3700",
    "CVE-2012-3701",
    "CVE-2012-3702",
    "CVE-2012-3703",
    "CVE-2012-3704",
    "CVE-2012-3705",
    "CVE-2012-3706",
    "CVE-2012-3707",
    "CVE-2012-3708",
    "CVE-2012-3709",
    "CVE-2012-3710",
    "CVE-2012-3711",
    "CVE-2012-3712"
  );
  script_bugtraq_id(
    51041,
    51641,
    51911,
    52031,
    52271,
    52674,
    52762,
    52913,
    53309,
    53540,
    54203,
    54680,
    55534,
    57027
  );

  script_name(english:"Apple iTunes < 10.7 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version 10.7. It
is, therefore, affected by multiple memory corruption vulnerabilities
in the WebKit component.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT202598");
  script_set_attribute(attribute:"see_also", value:"https://lists.apple.com/archives/security-announce/2012/Sep/msg00001.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes 10.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1521");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("iTunes/sharing");
  script_require_ports("Services/www", 3689);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

get_kb_item_or_exit("iTunes/" + port + "/enabled");

type = get_kb_item_or_exit("iTunes/" + port + "/type");
source = get_kb_item_or_exit("iTunes/" + port + "/source");
version = get_kb_item_or_exit("iTunes/" + port + "/version");

if (type != 'Windows') audit(AUDIT_OS_NOT, "Windows");

fixed_version = "10.7";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
