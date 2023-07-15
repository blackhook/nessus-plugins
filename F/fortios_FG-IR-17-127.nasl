#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100998);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2017-7734", "CVE-2017-7735");
  script_bugtraq_id(99098);

  script_name(english:"Fortinet FortiOS 5.2.x / 5.3.x / 5.4.x < 5.4.5 Multiple XSS (FG-IR-17-127)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiOS running on the remote device is 5.2.x,
5.3.x, or 5.4.x prior to 5.4.4. It is, therefore, affected by multiple
cross-site scripting (XSS) vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists when
    saving configuration revisions due to improper
    validation of user-supplied input to comments before
    returning it to users. An authenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2017-7734)

  - A cross-site scripting (XSS) vulnerability exists when
    creating or editing user groups due to improper
    validation of user-supplied input to groups before
    returning it to users. An authenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2017-7735)");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-17-127");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app_info = vcf::get_app_info(app:"FortiOS", kb_ver:"Host/Fortigate/version", webapp:true);

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { "min_version" : "5.2.0", "max_version" : "5.4.4", "fixed_version" : "5.4.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:true});
