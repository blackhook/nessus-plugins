#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90566);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2016-4059",
    "CVE-2016-4060",
    "CVE-2016-4061",
    "CVE-2016-4062",
    "CVE-2016-4063",
    "CVE-2016-4064",
    "CVE-2016-4065"
  );
  script_xref(name:"ZDI", value:"ZDI-16-211");
  script_xref(name:"ZDI", value:"ZDI-16-212");
  script_xref(name:"ZDI", value:"ZDI-16-213");
  script_xref(name:"ZDI", value:"ZDI-16-214");
  script_xref(name:"ZDI", value:"ZDI-16-215");
  script_xref(name:"ZDI", value:"ZDI-16-216");
  script_xref(name:"ZDI", value:"ZDI-16-217");
  script_xref(name:"ZDI", value:"ZDI-16-218");
  script_xref(name:"ZDI", value:"ZDI-16-219");
  script_xref(name:"ZDI", value:"ZDI-16-220");
  script_xref(name:"ZDI", value:"ZDI-16-221");
  script_xref(name:"ZDI", value:"ZDI-16-222");

  script_name(english:"Foxit PhantomPDF < 7.3.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
7.3.4. It is, therefore, affected by multiple vulnerabilities :

  - A use-after-free error exists that is triggered when
    handling FlateDecode streams. An unauthenticated,
    remote attacker can exploit this, via a crafted PDF
    file, to dereference already freed memory, resulting in
    a denial of service or the execution of arbitrary code.
    (CVE-2016-4059)

  - A use-after-free error exists that is related to the
    TimeOut() function. An unauthenticated, remote attacker
    can exploit this, via a crafted PDF file, to dereference
    already freed memory, resulting in a denial of service
    or the execution of arbitrary code. (CVE-2016-4060)

  - An unspecified flaw exists that is triggered when
    parsing content streams. An unauthenticated, remote
    attacker can exploit this to crash the application,
    resulting in a denial of service. (CVE-2016-4061)

  - An unspecified flaw exists that is triggered when
    recursively triggering PDF format errors. An
    unauthenticated, remote attacker can exploit this to
    cause the application to stop responding, resulting in a
    denial of service. (CVE-2016-4062)

  - A use-after-free error exists that is triggered when
    handling object revision numbers. An unauthenticated,
    remote attacker can exploit this, via a crafted PDF
    file, to dereference already freed memory, resulting in
    a denial of service or the execution of arbitrary code.
    (CVE-2016-4063)

  - A use-after-free error exists that is triggered when
    handling XFA re-layouts. An unauthenticated, remote
    attacker can exploit this to dereference already freed
    memory, resulting in a denial of service or the
    execution of arbitrary code. (CVE-2016-4064)

  - An out-of-bounds read error exists that is triggered
    when decoding BMP, GIF, and JPEG images during PDF
    conversion. An unauthenticated, remote attacker can
    exploit this to disclose sensitive memory contents or
    cause a denial of service. (CVE-2016-4065)

  - An unspecified use-after-free error exists that allows
    an unauthenticated, remote attacker to dereference
    already freed memory, resulting in a denial of service
    or the execution of arbitrary code.

  - A use-after-free error exists that is triggered when
    handling JavaScript API calls when closing a document.
    An unauthenticated, remote attacker can exploit this,
    via a crafted PDF file, to dereference already freed
    memory, resulting in a denial of service or the
    execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-211/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-212/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-213/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-214/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-215/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-216/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-217/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-218/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-219/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-220/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-221/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-222/");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 7.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4065");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

fixed_version = "7.3.4.311";
appname = "FoxitPhantomPDF";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install["path"];
version = install["version"];
name = install["Application Name"];
port = get_kb_item("SMB/transport");
if (!port)
  port = 445;

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  security_report_v4(port:port, extra:
    '\n  Application Name  : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version,
    severity:SECURITY_WARNING);
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, name, version);
}
exit(0);
