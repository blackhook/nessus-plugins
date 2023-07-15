#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60127);
  script_version("1.12");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2011-2845",
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
    "CVE-2011-3067",
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
    "CVE-2011-3426",
    "CVE-2011-3913",
    "CVE-2011-3924",
    "CVE-2011-3926",
    "CVE-2011-3958",
    "CVE-2011-3966",
    "CVE-2011-3968",
    "CVE-2011-3969",
    "CVE-2011-3971",
    "CVE-2012-0678",
    "CVE-2012-0679",
    "CVE-2012-0680",
    "CVE-2012-0682",
    "CVE-2012-0683",
    "CVE-2012-1520",
    "CVE-2012-1521",
    "CVE-2012-2815",
    "CVE-2012-3589",
    "CVE-2012-3590",
    "CVE-2012-3591",
    "CVE-2012-3592",
    "CVE-2012-3593",
    "CVE-2012-3594",
    "CVE-2012-3595",
    "CVE-2012-3596",
    "CVE-2012-3597",
    "CVE-2012-3599",
    "CVE-2012-3600",
    "CVE-2012-3603",
    "CVE-2012-3604",
    "CVE-2012-3605",
    "CVE-2012-3608",
    "CVE-2012-3609",
    "CVE-2012-3610",
    "CVE-2012-3611",
    "CVE-2012-3615",
    "CVE-2012-3618",
    "CVE-2012-3620",
    "CVE-2012-3625",
    "CVE-2012-3626",
    "CVE-2012-3627",
    "CVE-2012-3628",
    "CVE-2012-3629",
    "CVE-2012-3630",
    "CVE-2012-3631",
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
    "CVE-2012-3644",
    "CVE-2012-3645",
    "CVE-2012-3646",
    "CVE-2012-3650",
    "CVE-2012-3653",
    "CVE-2012-3655",
    "CVE-2012-3656",
    "CVE-2012-3661",
    "CVE-2012-3663",
    "CVE-2012-3664",
    "CVE-2012-3665",
    "CVE-2012-3666",
    "CVE-2012-3667",
    "CVE-2012-3668",
    "CVE-2012-3669",
    "CVE-2012-3670",
    "CVE-2012-3674",
    "CVE-2012-3678",
    "CVE-2012-3679",
    "CVE-2012-3680",
    "CVE-2012-3681",
    "CVE-2012-3682",
    "CVE-2012-3683",
    "CVE-2012-3686",
    "CVE-2012-3689",
    "CVE-2012-3690",
    "CVE-2012-3691",
    "CVE-2012-3693",
    "CVE-2012-3694",
    "CVE-2012-3695",
    "CVE-2012-3696",
    "CVE-2012-3697"
  );
  script_bugtraq_id(
    54669,
    54680,
    54683,
    54686,
    54687,
    54688,
    54692,
    54693,
    54694,
    54695,
    54696,
    54697,
    54700,
    54703,
    57027
  );

  script_name(english:"Mac OS X : Apple Safari < 6.0 Multiple Vulnerabilities");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
earlier than 6.0.  It is, therefore, potentially affected by several
issues :

  - An unspecified cross-site scripting issue exists.
    (CVE-2012-0678)

  - An error in the handling of 'feed://' URLs can allow
    local files to be disclosed to remote servers.
    (CVE-2012-0679)

  - Password input elements are auto completed even when
    a webpage specifically forbids it. (CVE-2012-0680)

  - A cross-site scripting issue exists due to improper
    handling of the HTTP 'Content-Disposition' header
    value of 'attachment'. (CVE-2011-3426)

  - Numerous issues exist in WebKit. (CVE-2011-2845,
    CVE-2011-3016, CVE-2011-3021, CVE-2011-3027,
    CVE-2011-3032, CVE-2011-3034, CVE-2011-3035,
    CVE-2011-3036, CVE-2011-3037, CVE-2011-3038,
    CVE-2011-3039, CVE-2011-3040, CVE-2011-3041,
    CVE-2011-3042, CVE-2011-3043, CVE-2011-3044,
    CVE-2011-3050, CVE-2011-3053, CVE-2011-3059,
    CVE-2011-3060, CVE-2011-3064, CVE-2011-3067,
    CVE-2011-3068, CVE-2011-3069, CVE-2011-3071,
    CVE-2011-3073, CVE-2011-3074, CVE-2011-3075,
    CVE-2011-3076, CVE-2011-3078, CVE-2011-3081,
    CVE-2011-3086, CVE-2011-3089, CVE-2011-3090,
    CVE-2011-3913, CVE-2011-3924, CVE-2011-3926,
    CVE-2011-3958, CVE-2011-3966, CVE-2011-3968,
    CVE-2011-3969, CVE-2011-3971, CVE-2012-0682,
    CVE-2012-0683, CVE-2012-1520, CVE-2012-1521,
    CVE-2012-2815, CVE-2012-3589, CVE-2012-3590,
    CVE-2012-3591, CVE-2012-3592, CVE-2012-3593,
    CVE-2012-3594, CVE-2012-3595, CVE-2012-3596,
    CVE-2012-3597, CVE-2012-3599, CVE-2012-3600,
    CVE-2012-3603, CVE-2012-3604, CVE-2012-3605,
    CVE-2012-3608, CVE-2012-3609, CVE-2012-3610,
    CVE-2012-3611, CVE-2012-3615, CVE-2012-3618,
    CVE-2012-3620, CVE-2012-3625, CVE-2012-3626,
    CVE-2012-3627, CVE-2012-3628, CVE-2012-3629,
    CVE-2012-3630, CVE-2012-3631, CVE-2012-3633,
    CVE-2012-3634, CVE-2012-3635, CVE-2012-3636,
    CVE-2012-3637, CVE-2012-3638, CVE-2012-3639,
    CVE-2012-3640, CVE-2012-3641, CVE-2012-3642,
    CVE-2012-3644, CVE-2012-3645, CVE-2012-3646,
    CVE-2012-3650, CVE-2012-3653, CVE-2012-3655,
    CVE-2012-3656, CVE-2012-3661, CVE-2012-3663,
    CVE-2012-3664, CVE-2012-3665, CVE-2012-3666,
    CVE-2012-3667, CVE-2012-3668, CVE-2012-3669,
    CVE-2012-3670, CVE-2012-3674, CVE-2012-3678,
    CVE-2012-3679, CVE-2012-3680, CVE-2012-3681,
    CVE-2012-3682, CVE-2012-3683, CVE-2012-3686,
    CVE-2012-3689, CVE-2012-3690, CVE-2012-3691,
    CVE-2012-3693, CVE-2012-3694, CVE-2012-3695,
    CVE-2012-3696, CVE-2012-3697)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5400");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Jul/msg00000.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari 6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1521");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.7([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.7");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "6.0";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Safari", version);
