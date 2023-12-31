#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17208);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-0546");
  script_bugtraq_id(12636);

  script_name(english:"Cyrus IMAP Server < 2.2.11 Multiple Remote Overflows");

  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by multiple buffer overflow issues.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Cyrus IMAP server is affected by
off-by-one errors in its imapd annotate extension and its cached
header handling which can be triggered by an authenticated user, a
buffer overflow in fetchnews that can be triggered by a peer news
admin, and an unspecified stack-based buffer overflow in imapd.");
  # http://web.archive.org/web/20060616064839/http://cyrusimap.web.cmu.edu/imapd/changes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6eef2b3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cyrus IMAP server version 2.2.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cmu:cyrus_imap_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("cyrus_imap_prelogin_overflow.nasl");
  script_require_ports("Services/imap", 143);

  exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if(!port) port = 143;

banner = get_kb_item("imap/" + port + "/Cyrus");
if ( ! banner ) exit(0);
if(egrep(pattern:"^(1\..*|2\.0\..*|2\.1\.[1-9][^0-9]|2\.1\.1[01])[0-9]*$", string:banner))
    security_hole(port);
