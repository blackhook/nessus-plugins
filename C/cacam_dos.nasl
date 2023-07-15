#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(20840);
  script_version("1.20");
  script_cve_id("CVE-2006-0529", "CVE-2006-0530");
  script_bugtraq_id(16475);

  script_name(english:"CA Multiple Products Message Queuing Multiple Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote messaging service." );
  script_set_attribute(attribute:"description", value:
"The remote version of CA Message Queuing Service is vulnerable
to two flaws that could lead to a denial of service :

  - Improper handling of specially crafted TCP packets on
    port 4105 (CVE-2006-0529)

  - Failure to handle spoofed UDP CAM requests
    (CVE-2006-0530)"
 );
  script_set_attribute(attribute:"see_also", value:"https://cxsecurity.com/issue/WLB-2006020014");
  script_set_attribute(attribute:"solution", value:
"CA has released a set of patches for CAM 1.05, 1.07 and 1.11." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-0529");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/03");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/02");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ca:messaging");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");

  script_dependencies("cacam_detect.nasl");
  script_require_keys("CA/MessageQueuing");
  script_require_ports(4105);
  exit(0);
}

var version = get_kb_item ("CA/MessageQueuing");
if (isnull(version))
  exit (0);

var port = 4105;

var main = ereg_replace (pattern:"^([0-9]+)\.[0-9]+ \(Build [0-9]+_[0-9]+\)$", string:version, replace:"\1");
var revision = ereg_replace (pattern:"^[0-9]+\.([0-9]+) \(Build [0-9]+_[0-9]+\)$", string:version, replace:"\1");

var build = ereg_replace (pattern:"^[0-9]+\.[0-9]+ \(Build ([0-9]+)_[0-9]+\)$", string:version, replace:"\1");
var build_rev = ereg_replace (pattern:"^[0-9]+\.[0-9]+ \(Build [0-9]+_([0-9]+)\)$", string:version, replace:"\1");


var main = int(main);
var revision = int (revision);
var build = int(build);
var build_rev = int (build_rev);


# vulnerable :
# 1.05
# < 1.07 build 220_16
# 1.07 build 230 & 231
# < 1.11 build 29_20

var report = ' Please upgrade to either version 1.07 build 220_16 or version 1.11 build 29_20 and above\n ';

if ((main < 1) || ((main == 1) && (revision < 7)) || ((main == 1) && (revision > 7) && (revision < 11)))
{
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else if (main == 1)
{
 if (revision == 7)
 {
  if ((build < 220) || ((build == 220) && (build_rev < 16)))
    security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  else if ((build == 230) || (build == 231))
    security_report_v4(port:port, severity:SECURITY_WARNING);
 }
  else if (revision == 11)
 {
  if ((build < 29) || ((build == 29) && (build_rev < 20)))
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
 }
}
