#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102682);
  script_version("1.5");
  script_cvs_date("Date: 2019/01/02 11:18:37");


  script_name(english:"Foxit PhantomPDF < 7.3.15 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
7.3.15. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified NULL pointer dereference flaw allows an
    unauthenticated, remote attacker to cause a crash.

  - An unspecified flaw related to use of uninitialized memory allows
    an unauthenticated, remote attacker to cause a crash.

  - An unspecified flaw in the Trust Manager causes the setting to
    disable JavaScript actions to be ignored, thus allowing an
    unauthenticated, remote attacker to execute arbitrary JavaScript
    functions.

  - An unspecified use-after-free error exists that allows an
    unauthenticated, remote attacker to dereference already freed
    memory, resulting in a denial of service or the execution of
    arbitrary code.

  - An unspecified out-of-bounds read flaw allows an unauthenticated,
    remote attacker to disclose potentially sensitive information.

  - An unspecified out-of-bounds write flaw allows an unauthenticated,
    remote attacker to execute arbitrary code.");

  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 7.3.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"FoxitPhantomPDF", win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

# < 7.3.15
constraints = [
  { "fixed_version" : "7.3.15" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
