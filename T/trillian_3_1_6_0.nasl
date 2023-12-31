#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25547);
  script_version("1.18");

  script_cve_id("CVE-2007-3305");
  script_bugtraq_id(24523);

  script_name(english:"Trillian < 3.1.6.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application that is
affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host reportedly is
affected by a heap-based buffer overflow issue involving improper
handling of UTF-8 sequences when word-wrapping UTF-8 text.  A remote
attacker may be able to leverage these issues to execute arbitrary
code as the current user." );
 # http://www.verisigninc.com/en_US/cyber-security/security-intelligence/vulnerability-reports/articles/index.xhtml?id=545
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcd19445" );
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/471673/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20160320091220/http://blog.trillian.im/?p=150" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.6.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/18");
 script_cvs_date("Date: 2018/11/15 20:50:29");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:trillian:trillian");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");

  script_dependencies("trillian_installed.nasl");
  script_require_keys("SMB/Trillian/Version");

  exit(0);
}


ver = get_kb_item("SMB/Trillian/Version");
if (ver && ver =~ "^([0-2]\.|3\.(0\.|1\.[0-5]\.))")
  security_hole(get_kb_item("SMB/transport"));
