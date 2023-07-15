#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119811);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/11");

  script_name(english:"Script Src Integrity Check");
  script_summary(english:"Report external script resources not using integrity.");
  script_set_attribute(attribute:"synopsis", value:
                       "Report external script resources not using integrity.");
  script_set_attribute(attribute:"description", value:
"The remote host may be vulnerable to payment entry data exfiltration 
due to javascript included from potentially untrusted and unverified 
third parties script src.

If the host is controlled by a 3rd party, ensure that the 3rd party
is PCI DSS compliant.");

  # https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9e76c4f");
  script_set_attribute(attribute:"see_also", value:"https://www.w3.org/TR/SRI/");
  # https://shkspr.mobi/blog/2018/11/major-sites-running-unauthenticated-javascript-on-their-payment-pages/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f39144f8");

  script_set_attribute(attribute:"solution", value:"Set script integrity checking on target script or remove target script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of vulnerability.");


  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmirror3.nbin");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2 && !get_kb_item("Settings/PCI_DSS"))
{
  exit(1, "This script only runs if 'Report paranoia' is set to 'Paranoid' or PCI Scan is Enabled.");
}

if (!query_scratchpad("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'JavascriptExtFiles';"))
{
  exit(0, "No javascript sources found by webmirror3.");
}

spad_jsext = query_scratchpad("SELECT script_data, path, port, page FROM JavascriptExtFiles");
report_list = make_array();
report = '';
foreach sje (spad_jsext)
{
  # We do not report on anything that has integrity checks
  if ('"integrity"' >< sje['script_data']) continue;

  attribute_list = deserialize(sje['script_data']);
  if (attribute_list['attributes'])
  {
    # We do not want to report on blank src scripts
    if (empty_or_null(attribute_list['attributes']['src'])) continue;
    report = 'Path : ' + sje['path'] + '\n';
    report += 'Parent : ' + sje['page'] + '\n';
    report += 'Attributes : \n';
    foreach attr (keys(attribute_list['attributes']))
    {
      report += ' - ' + attr + ' : ' + attribute_list['attributes'][attr] + '\n';
    }
  }

  report += '\n';

  if (report_list[sje['port']])
    report_list[sje['port']] += report;
  else 
    report_list[sje['port']] = report;

  report = '';
}

foreach report_port (keys(report_list))
{
  security_report_v4(port:report_port, extra:report_list[report_port], severity:SECURITY_HOLE);
}
