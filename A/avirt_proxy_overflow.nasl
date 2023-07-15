#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/03/30.


include("compat.inc");

if(description)
{
  script_id(11715);
  script_bugtraq_id(3904);
  script_cve_id("CVE-2002-0133");
  script_version ("1.19");
  script_name(english:"Avirt Multiple Product HTTP Proxy Overflow (deprecated)");
  script_summary(english:"Too long HTTP header kills the HTTP proxy server");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated." );
 script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it resulted in false positives without reliably detecting the vulnerability on the
intended target. Avirt software is not currently being distributed or maintained.");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Jan/224");
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/31");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2003-2020 Tenable Network Security, Inc.");
  script_family(english: "Web Servers");
  script_require_ports("Services/http_proxy", 8080);
  script_dependencie("find_service2.nasl", "http_version.nasl");
  exit(0);
}

exit(0, "This plugin has been deprecated.");
