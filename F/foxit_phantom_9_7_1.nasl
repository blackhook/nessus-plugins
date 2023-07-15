#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133525);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2019-5126",
    "CVE-2019-5130",
    "CVE-2019-5131",
    "CVE-2019-5145"
  );
  script_xref(name:"ZDI", value:"ZDI-CAN-9102");
  script_xref(name:"ZDI", value:"ZDI-CAN-9358");
  script_xref(name:"ZDI", value:"ZDI-CAN-9400");
  script_xref(name:"ZDI", value:"ZDI-CAN-9406");
  script_xref(name:"ZDI", value:"ZDI-CAN-9407");
  script_xref(name:"ZDI", value:"ZDI-CAN-9413");
  script_xref(name:"ZDI", value:"ZDI-CAN-9414");
  script_xref(name:"ZDI", value:"ZDI-CAN-9415");
  script_xref(name:"ZDI", value:"ZDI-CAN-9416");
  script_xref(name:"ZDI", value:"ZDI-CAN-9560");
  script_xref(name:"ZDI", value:"ZDI-CAN-9591");
  script_xref(name:"ZDI", value:"ZDI-CAN-9606");
  script_xref(name:"ZDI", value:"ZDI-CAN-9640");
  script_xref(name:"ZDI", value:"ZDI-CAN-9862");
  script_xref(name:"IAVA", value:"2020-A-0049-S");

  script_name(english:"Foxit PhantomPDF < 9.7.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
9.7.1. It is, therefore, affected by multiple vulnerabilities:

  - A use-after-free error exists related to handling
    watermarks, AcroForm objects, text fields, or
    JavaScript field objects that allows arbitrary code
    execution. (CVE-2019-5126, CVE-2019-5130,
    CVE-2019-5131, CVE-2019-5145, ZDI-CAN-9358,
    ZDI-CAN-9640, ZDI-CAN-9400, ZDI-CAN-9862)

  - An integer overflow or out-of-bounds read/write error
    exists related to handling JPEG/JPG2000 images or JP2
    streams that allows memory contents disclosure.
    (ZDI-CAN-9102, ZDI-CAN-9606, ZDI-CAN-9407,
    ZDI-CAN-9413, ZDI-CAN-9414, ZDI-CAN-9415,
    ZDI-CAN-9406, ZDI-CAN-9416)

  - An out-of-bounds write error and a use-after-free
    error exist related to handling HTML to PDF conversion
    that allows arbitrary code execution. (ZDI-CAN-9591,
    ZDI-CAN-9560)

  - A use-after-free error exists related to handling
    documents that are missing dictionaries that allows
    unspecified impact.

  - A stack overflow error exists related to handling
    indirect object references that allows application
    crashes and other unspecified impact.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9102/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9358/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9400/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9406/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9407/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9413/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9414/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9415/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9416/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9560/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9591/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9606/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9640/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-9862/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 9.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5145");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include('vcf.inc');

app = 'FoxitPhantomPDF';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'max_version' : '9.7.0.29455', 'fixed_version' : '9.7.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
