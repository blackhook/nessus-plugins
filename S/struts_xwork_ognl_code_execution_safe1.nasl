#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/11/18 due to timing based false positives.
# Local plugin added to replace CVE coverage in struts_2_3_1_1_real.nasl.

include('compat.inc');

if (description)
{
  script_id(57691);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2012-0392");
  script_bugtraq_id(51257);
  script_xref(name:"EDB-ID", value:"18329");

  script_name(english:"Apache Struts 2 Multiple Remote Code Execution and File Overwrite Vulnerabilities (safe check) (deprecated)");
  script_summary(english:"Fingerprints the vulnerability by doing multiple sleeps.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This plugin has been deprecated due to relying on a timing based check that is prone to false positives. A local
plugin will be added that covers this CVE."
  );
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-008.html");
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0392");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 8080, 80);

  exit(0);
}
exit(0, "This plugin has been deprecated. Use struts_2_3_1_1_real.nasl instead.");
