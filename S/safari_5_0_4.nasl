#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52613);
  script_version("1.18");
  script_cvs_date("Date: 2018/07/27 18:38:15");

  script_cve_id(
    "CVE-2010-1205",
    "CVE-2010-1824",
    "CVE-2010-2249",
    "CVE-2010-4008",
    "CVE-2010-4494",
    "CVE-2011-0111",
    "CVE-2011-0112",
    "CVE-2011-0113",
    "CVE-2011-0114",
    "CVE-2011-0115",
    "CVE-2011-0116",
    "CVE-2011-0117",
    "CVE-2011-0118",
    "CVE-2011-0119",
    "CVE-2011-0120",
    "CVE-2011-0121",
    "CVE-2011-0122",
    "CVE-2011-0123",
    "CVE-2011-0124",
    "CVE-2011-0125",
    "CVE-2011-0126",
    "CVE-2011-0127",
    "CVE-2011-0128",
    "CVE-2011-0129",
    "CVE-2011-0130",
    "CVE-2011-0131",
    "CVE-2011-0132",
    "CVE-2011-0133",
    "CVE-2011-0134",
    "CVE-2011-0135",
    "CVE-2011-0136",
    "CVE-2011-0137",
    "CVE-2011-0138",
    "CVE-2011-0139",
    "CVE-2011-0140",
    "CVE-2011-0141",
    "CVE-2011-0142",
    "CVE-2011-0143",
    "CVE-2011-0144",
    "CVE-2011-0145",
    "CVE-2011-0146",
    "CVE-2011-0147",
    "CVE-2011-0148",
    "CVE-2011-0149",
    "CVE-2011-0150",
    "CVE-2011-0151",
    "CVE-2011-0152",
    "CVE-2011-0153",
    "CVE-2011-0154",
    "CVE-2011-0155",
    "CVE-2011-0156",
    "CVE-2011-0160",
    "CVE-2011-0161",
    "CVE-2011-0163",
    "CVE-2011-0165",
    "CVE-2011-0166",
    "CVE-2011-0167",
    "CVE-2011-0168",
    "CVE-2011-0169",
    "CVE-2011-0170",
    "CVE-2011-0191",
    "CVE-2011-0192"
  );
  script_bugtraq_id(
    41174,
    44779,
    46657,
    46658,
    46659,
    46677,
    46684,
    46686,
    46687,
    46688,
    46689,
    46690,
    46691,
    46692,
    46693,
    46694,
    46695,
    46696,
    46698,
    46699,
    46700,
    46701,
    46702,
    46704,
    46705,
    46706,
    46707,
    46708,
    46709,
    46710,
    46711,
    46712,
    46713,
    46714,
    46715,
    46716,
    46717,
    46718,
    46719,
    46720,
    46721,
    46722,
    46723,
    46724,
    46725,
    46726,
    46727,
    46728,
    46744,
    46745,
    46746,
    46747,
    46748,
    46749,
    46808,
    46809,
    46811,
    46814,
    46816
  );

  script_name(english:"Safari < 5.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Safari installed on the remote Windows host is earlier
than 5.0.4.  It therefore is potentially affected by several issues in
the following components :

  - ImageIO

  - libxml

  - WebKit"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4566");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Safari 5.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/Safari/FileVersion");

version_ui = get_kb_item("SMB/Safari/ProductVersion");
if (isnull(version_ui)) version_ui = version;

if (ver_compare(ver:version, fix:"5.33.20.27") == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/Safari/Path");
    if (isnull(path)) path = "n/a";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 5.0.4 (7533.20.27)\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The remote host is not affected since Safari " + version_ui + " is installed.");
