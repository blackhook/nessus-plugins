#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93343);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2015-8383",
    "CVE-2015-8386",
    "CVE-2015-8387",
    "CVE-2015-8389",
    "CVE-2015-8390",
    "CVE-2015-8391",
    "CVE-2015-8393",
    "CVE-2015-8394"
  );
  script_bugtraq_id(
    79810,
    82990
  );

  script_name(english:"Tenable SecurityCenter < 5.3.0 Multiple Vulnerabilities (TNS-2016-04)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The Tenable SecurityCenter application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host is
either prior to version 5.3.0 or is missing a security patch. It is,
therefore, affected by multiple vulnerabilities in the Perl-Compatible
Regular Expressions (PCRE) library bundled with PHP :

  - An overflow condition exists in the PCRE library due to
    improper validation of user-supplied input when handling
    repeated conditional groups. An attacker can exploit
    this, via a specially crafted regular expression, to
    cause a buffer overflow, resulting in a denial of
    service condition. (CVE-2015-8383)

  - An overflow condition exists in the PCRE library due to
    improper validation of user-supplied input when handling
    mutual recursions within a 'lookbehind' assertion. An
    attacker can exploit this to cause a stack-based buffer
    overflow, resulting in a denial of service condition.
    (CVE-2015-8386)

  - An integer overflow condition exists in the PCRE library
    due to improper validation of user-supplied input when
    handling subroutine calls. An attacker can exploit this,
    via a specially crafted regular expression, to cause a
    denial of service condition. (CVE-2015-8387)

  - A flaw exists in the PCRE library due to improper
    handling of the /(?:|a|){100}x/ pattern or other related
    patterns. An attacker can exploit this, via a specially
    crafted regular expression, to cause an infinite
    recursion, resulting in a denial of service condition.
    (CVE-2015-8389)

  - A flaw exists in the PCRE library due to improper
    handling of the [: and \\ substrings in character
    classes. An attacker can exploit this, via a specially
    crafted regular expression, to cause an uninitialized
    memory read, resulting in a denial of service condition.
    (CVE-2015-8390)

  - A flaw exists in the PCRE library in the pcre_compile()
    function in pcre_compile.c due to improper handling of
    [: nesting. An attacker can exploit this, via a
    specially crafted regular expression, to cause an
    excessive consumption of CPU resources, resulting in a
    denial of service condition. (CVE-2015-8391)

  - A flaw exists in the PCRE library due to improper
    handling of the '-q' option for binary files. An
    attacker can exploit this, via a specially crafted file,
    to disclose sensitive information. (CVE-2015-8393)

  - An integer overflow condition exists in the PCRE library
    due to improper validation of user-supplied input when
    handling the (?(<digits>) and (?(R<digits>) conditions.
    An attacker can exploit this, via a specially crafted
    regular expression, to cause a denial of service
    condition. (CVE-2015-8394)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-04");
  script_set_attribute(attribute:"see_also", value:"https://secure.php.net/ChangeLog-5.php#5.6.18");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SecurityCenter version 5.3.0 or later. Alternatively, apply
patch SC-201603.1-5.x-rh5-64.tgz / SC-201603.1-5.x-rh6-64.tgz.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_keys("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/SecurityCenter/support/php/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

sc_ver  = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
version = get_kb_item_or_exit("Host/SecurityCenter/support/php/version");

fix = "5.6.18"; # default to known php release branch used in advisory
if (version =~ "^5\.4\.") fix = "5.4.45";

if (ver_compare(ver:sc_ver, fix:"4.8.2", strict:FALSE) < 0)
  fix = FALSE;

if (!fix || ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  # If there is a patch available report it, otherwise the fix as SC 5.3.0
  if (fix)
  {
    order  = make_list("SecurityCenter version", "SecurityCenter PHP version", "Fixed PHP version");
    report = make_array(order[0], sc_ver, order[1], version, order[2], fix);
  }
  else
  {
    order  = make_list("Installed version", "Fixed version");
    report = make_array(order[0], sc_ver, order[1], "5.3.0");
  }
  report = report_items_str(report_items:report, ordered_fields:order);
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "PHP (within SecurityCenter)", version);
