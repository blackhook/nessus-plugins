#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25700);
 script_version("1.29");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/15");

 script_cve_id("CVE-2006-7192", "CVE-2007-0041", "CVE-2007-0042", "CVE-2007-0043");
 script_bugtraq_id(20753, 24778, 24791, 24811);
 script_xref(name:"IAVA", value:"2007-A-0037-S");
 script_xref(name:"MSFT", value:"MS07-040");
 script_xref(name:"MSKB", value:"928365");
 script_xref(name:"MSKB", value:"928367");
 script_xref(name:"MSKB", value:"929729");

 script_name(english:"MS07-040: Vulnerabilities in .NET Framework Could Allow Remote Code Execution (931212) (uncredentialed check)");
 script_summary(english:"Determines the version of the .NET framework by looking at the IIS headers");

 script_set_attribute(
  attribute:"synopsis",
  value:"The remote .Net Framework is vulnerable to a code execution attack."
 );
 script_set_attribute(attribute:"description", value:
"The remote web server is running a version of the ASP.NET framework
that contains multiple vulnerabilities :

  - A PE Loader vulnerability could allow an attacker to
    execute arbitrary code with the privilege of the
    logged-on user.

  - A ASP.NET NULL byte termination vulnerability could
    allow an attacker to retrieve contents from the web
    server.

  - A JIT compiler vulnerability could allow an attacker to
    execute arbitrary code with the privilege of the
    logged-on user." );
 # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-040
 script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?14274f59");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.0, 1.1 and
2.0." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(119, 200);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/05");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/11");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2020 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("dotnet_framework_version.nasl");
 script_require_ports("Services/www/ASP.Net");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb =  get_kb_item("www/" + port + "/Microsoft_.NET_Framework_Version");
if ( ! kb ) exit(0);

v = split(kb, sep:'.', keep:FALSE);
for ( i = 0 ; i < max_index(v) ; i ++ ) v[i] = int(v[i]);

if ( (v[0] == 1 && v[1] == 0 && v[2] < 3705) ||
     (v[0] == 1 && v[1] == 0 && v[2] == 3705 && v[3] < 6060)  || # 1.0SP3

     (v[0] == 1 && v[1] == 1 && v[2] < 4322) ||
     (v[0] == 1 && v[1] == 1 && v[2] == 4322 && v[3] < 2407) ||  # 1.1 SP1

     (v[0] == 2 && v[1] == 0 && v[2] < 50727 ) ||
     (v[0] == 2 && v[1] == 0 && v[2] == 50727 && v[3] < 832 ) ) security_hole(port);
