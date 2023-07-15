#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56212);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_xref(name:"IAVA", value:"0001-A-0505");

  script_name(english:"Adobe Acrobat Unsupported Version Detection");
  script_summary(english:"Checks the Adobe Acrobat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Adobe Acrobat.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Adobe
Acrobat on the remote Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://prodesigntools.com/adobe-acrobat-dc-document-cloud.html 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d63c933d");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Adobe Acrobat that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Acrobat/Version");

  exit(0);
}

var versions, withdrawl_announcements, supported_versions, info, info2,
version, path, report_version, i, ver, version_highlevel, v, port, be;

versions = get_kb_list('SMB/Acrobat/Version');
if (isnull(versions)) exit(0, 'The "SMB/Acrobat/Version" KB list is missing.');

var eos_dates = make_array(
  '17', 'November 15, 2022',
  '15', 'July 7, 2020',
  '11', 'October 15, 2017',
  '10', 'November 15, 2015',
  '9', 'June 26, 2013',
  '8', 'November 3, 2011',
  '7', '',
  '6', '',
  '5', '',
  '4', '',
  '3', '',
  '2', '',
  '1', ''
);
withdrawl_announcements = make_array(
  '11', 'https://theblog.adobe.com/adobe-acrobat-xi-and-adobe-reader-xi-end-of-support/',
  '10', 'https://blogs.adobe.com/documentcloud/adobe-acrobat-x-and-adobe-reader-x-end-of-support/',
  '9', 'https://helpx.adobe.com/acrobat/kb/end-support-acrobat-8-reader.html', #Actual content is for 9
  '8', 'http://blogs.adobe.com/adobereader/2011/09/adobe-reader-and-acrobat-version-8-end-of-support.html'
);
supported_versions = 'Adobe Acrobat Standard / Pro / DC (2020) / 2022';

info = "";
info2 = "";

foreach version (versions)
{
  path   = get_kb_item("SMB/Acrobat/"+version+"/Path");
  report_version = get_kb_item("SMB/Acrobat/"+version+"/Version_UI");
  if (isnull(report_version))
    report_version = version;

  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);
  version_highlevel = ver[0];

  foreach v (keys(eos_dates))
  {
    if (v == version_highlevel)
    {
      register_unsupported_product(product_name:"Adobe Acrobat", version:version, cpe_base:"adobe:acrobat");

      info +=
        '\n  Path                : ' + path +
        '\n  Installed version   : ' + report_version;
      if (eos_dates[version_highlevel])
        info += '\n  End of support date : ' + eos_dates[version_highlevel];
      if (withdrawl_announcements[version_highlevel])
        info += '\n  Announcement        : ' + withdrawl_announcements[version_highlevel];
      info += '\n  Supported versions  : ' + supported_versions + '\n';
      break;
    }
  }
  info2 += " and " + report_version;
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0) security_report_v4(port:port, extra:info, severity:SECURITY_HOLE);
  else security_report_v4(port:port, severity:SECURITY_HOLE);

  exit(0);
}

if (info2)
{
 info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Acrobat " + info2 + " " + be + " installed.");
}
else exit(1, "Unexpected error - 'info2' is empty.");
