#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124413);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2018-20309",
    "CVE-2018-20310",
    "CVE-2018-20311",
    "CVE-2018-20312",
    "CVE-2018-20313",
    "CVE-2018-20314",
    "CVE-2018-20315",
    "CVE-2018-20316"
  );
  script_xref(name:"ZDI", value:"ZDI-CAN-7407");
  script_xref(name:"ZDI", value:"ZDI-CAN-7561");
  script_xref(name:"ZDI", value:"ZDI-CAN-7613");
  script_xref(name:"ZDI", value:"ZDI-CAN-7614");
  script_xref(name:"ZDI", value:"ZDI-CAN-7620");
  script_xref(name:"ZDI", value:"ZDI-CAN-7694");
  script_xref(name:"ZDI", value:"ZDI-CAN-7696");
  script_xref(name:"ZDI", value:"ZDI-CAN-7701");
  script_xref(name:"ZDI", value:"ZDI-CAN-7769");
  script_xref(name:"ZDI", value:"ZDI-CAN-7777");
  script_xref(name:"ZDI", value:"ZDI-CAN-7844");
  script_xref(name:"ZDI", value:"ZDI-CAN-7874");
  script_xref(name:"ZDI", value:"ZDI-CAN-7972");
  script_xref(name:"ZDI", value:"ZDI-CAN-8162");
  script_xref(name:"ZDI", value:"ZDI-CAN-8163");
  script_xref(name:"ZDI", value:"ZDI-CAN-8164");
  script_xref(name:"ZDI", value:"ZDI-CAN-8165");
  script_xref(name:"ZDI", value:"ZDI-CAN-8170");
  script_xref(name:"ZDI", value:"ZDI-CAN-8229");
  script_xref(name:"ZDI", value:"ZDI-CAN-8230");
  script_xref(name:"ZDI", value:"ZDI-CAN-8231");
  script_xref(name:"ZDI", value:"ZDI-CAN-8272");

  script_name(english:"Foxit PhantomPDF < 9.5.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
8.3.10. It is, therefore, affected by multiple vulnerabilities:

  - A heap-based buffer overflow condition exists in the 
    proxyCPDFAction, proxyCheckLicence, proxyDoAction, 
    proxyGetAppEdition, or proxyPreviewAction due to a stack buffer 
    overflow or out-of-bounds read. An authenticated, local attacker 
    can exploit this, via large integer or long string causing a 
    denial of service condition or the execution of arbitrary code.

  - A directory traversal vulnerability exists in the cPDF plugin due
    to unexpected javascript invocation resulting in remote code 
    execution. An unauthenticated, remote attacker can exploit this, 
    by invoking javascript through the console to write local files. 
    (ZDI-CAN-7407)

  - A integer overflow and crash condition exists in the XFA stuff 
    method due to the lack of proper validation of user-supplied 
    data. An attacker can explit this to disclose information. 
    (ZDI-CAN-7561)

  - A use-after-free, out-of-bounds read, and crash vulnerability 
    exists when converting HTML files to PDFs. An authenticated, 
    remote attacker can exploit this to disclose information
    or to execute arbitrary code. 
    (ZDI-CAN-7620/ZDI-CAN-7844/ZDI-CAN-8170)   

  - A out-of-bounds write and crash vulnerability exists. An 
    authenticated, remote attacker can exploit this to execute 
    arbitrary code. (ZDI-CAN-7613/ZDI-CAN-7614/ZDI-CAN-7701/
    ZDI-CAN-7972)

  - A use-after-free or out-of-bounds write and crash vulnerability 
    exists. An authenticated, local attacker can exploit this to 
    execute arbitrary code. (ZDI-CAN-7696/ZDI-CAN-7694)

  - A use-after-free vulnerability. An authenticated, 
    remote attacker can exploit this to execute arbitrary 
    code. (ZDI-CAN-7696/ZDI-CAN-7694/ZDI-CAN-7777/ZDI-CAN-7874)

  - A use-after-free, remote code execution, information 
    disclosure vulnerability exists when deleting Field with nested
    scripts. An authenticated, local attacker can exploit this to 
    execute arbitrary code. (ZDI-CAN-8162/ZDI-CAN-8163/ZDI-CAN-8164/
    ZDI-CAN-8165/ZDI-CAN-8229/ZDI-CAN-8230/ZDI-CAN-8231/ZDI-CAN-8272)");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7407/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7561/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7613/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7614/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7620/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7694/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7696/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7701/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7769/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7777/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7844/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7874/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7972/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8162/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8163/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8164/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8165/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8170/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8229/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8230/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8231/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8272/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 9.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20316");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include('vcf.inc');

app = 'FoxitPhantomPDF';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [{
  'min_version' : '9.0',
  'max_version' : '9.4.1.16828',
  'fixed_version' : '9.5.0'
  }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
