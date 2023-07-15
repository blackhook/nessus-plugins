#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101523);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
    "CVE-2017-10941",
    "CVE-2017-10942",
    "CVE-2017-10943",
    "CVE-2017-10944",
    "CVE-2017-10945",
    "CVE-2017-10946",
    "CVE-2017-10947",
    "CVE-2017-10948",
    "CVE-2017-10994"
  );
  script_bugtraq_id(99499);

  script_name(english:"Foxit PhantomPDF < 8.3.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
8.3.1. It is, therefore, affected by multiple vulnerabilities :

  - A use-after-free error exists in the AFParseDateEx()
    function. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted PDF document, to dereference already freed
    memory and execute arbitrary code. (CVE-2017-10941)

  - Multiple out-of-bounds read errors exist that are
    triggered when handling specially crafted PDF files. An
    unauthenticated, remote attacker can exploit these to
    disclose sensitive information. (CVE-2017-10942,
    CVE-2017-10943)

  - An out-of-bounds read error exists due to improper
    parsing of ObjStm objects. An unauthenticated, remote
    attacker can exploit this to disclose sensitive
    information. (CVE-2017-10944)

  - A use-after-free error exists in the app.alert()
    function. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted PDF document, to dereference already freed
    memory and execute arbitrary code. (CVE-2017-10945)

  - A use-after-free error exists in the setItem() function.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted PDF
    document, to dereference already freed memory and
    execute arbitrary code. (CVE-2017-10946)

  - A use-after-free error exists in the print() function.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted PDF
    document, to dereference already freed memory and
    execute arbitrary code. (CVE-2017-10947)

  - A use-after-free error exists in the app.execMenuItem()
    function. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted PDF document, to dereference already freed
    memory and execute arbitrary code. (CVE-2017-10948)

  - An unspecified arbitrary write flaw exists. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted PDF
    document, to execute arbitrary code. (CVE-2017-10994)

  - A NULL pointer dereference flaw exists that allows an
    unauthenticated, remote attacker to cause the
    application to crash, resulting in a denial of service
    condition.

  - A security bypass vulnerability exists in the Trust
    Manager due to a failure to honor the restriction of
    JavaScript actions. An unauthenticated, remote attacker
    can exploit this, by convincing a user to open a
    specially crafted PDF document, to execute arbitrary
    JavaScript functions.

  - An unspecified flaw exists that is triggered by the use
    of uninitialized data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 8.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10994");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include('vcf.inc');

app = 'FoxitPhantomPDF';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [{
  'min_version' : '8.0',
  'max_version' : '8.3.0.14878',
  'fixed_version' : '8.3.1'
  }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
