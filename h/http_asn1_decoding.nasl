#
# (C) Tenable Network Security, Inc.
#

# Thanks to Juliano Rizzo <juliano@corest.com> for suggesting to do
# the check using web NTML authentication.
#
# Credit for original advisory and blob: eEye
#


include("compat.inc");

if(description)
{
 script_id(12055);
 script_version ("1.55");

 script_cve_id("CVE-2003-0818");
 script_bugtraq_id(9633, 9635, 9743, 13300);
 script_xref(name:"MSFT", value:"MS04-007");
 script_xref(name:"MSKB", value:"828028");

 script_name(english:"MS04-007: ASN.1 Vulnerability Could Allow Code Execution (828028) (uncredentialed check) (HTTP)");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a memory corruption
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host has an ASN.1 library with a vulnerability that
could allow an attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to send a specially
crafted ASN.1 encoded packet with improperly advertised lengths.

This particular check sent a malformed HTML authorization packet and
determined that the remote host is not patched." );
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2004/ms04-007" );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Feb/269" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS04-007 Microsoft ASN.1 Library Bitstring Heap Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/10");
 script_cvs_date("Date: 2018/11/15 20:50:27");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/02/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_summary(english:"Checks if the remote host has a patched ASN.1 decoder (828028)");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_require_ports("Services/www", 80); 
 script_dependencies("http_version.nasl");
 script_require_keys("www/iis");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function gssapi(oid, spenego)
{
 local_var len;
 len = strlen(oid) + strlen(spenego);
 return raw_string(0x60, 0x84,0,0,0,len % 256) + oid + spenego;
}

# Returns SPNEGO OID (1.3.6.5.5.2)
function oid()
{
 local_var oid, len;
 oid = raw_string(0x2b, 0x06, 0x01, 0x05, 0x05, 0x02);
 len = strlen(oid);
 return raw_string(0x06, 0x83,0,0,len % 256) + oid;
}


# ANS.1 encodes our negTokenInit blob
function spenego(negTokenInit)
{
 local_var len;
 len = strlen(negTokenInit);

 return raw_string(0xa0, 0x82,0,len % 256) + negTokenInit;
}


# ASN.1 encodes our mechType and mechListMIC
function negTokenInit(mechType, mechListMIC)
{
 local_var len, len2, data, data2;

 len = strlen(mechType); 
 data = raw_string(0xa0, len + 2, 0x30, len);
 len += strlen(data) + strlen(mechListMIC) + 8;

 len2 = strlen(mechListMIC);
 data2 = raw_string(0xa3, len2 + 6, 0x30, len2 + 4, 0xa0, len2 - 8 , 0x3b, 0x2e);


 return raw_string(0x30,0x81,len % 256) + data + mechType + data2 + mechListMIC;
}

# Returns OID 1.3.6.1.4.1.311.2.2.10 (NTMSSP)
function mechType()
{
 return raw_string(0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a);
}

function mechListMIC()
{
 local_var data;

 data = raw_string(0x04, 0x81, 0x01, 0x25) +
       	raw_string(0x24, 0x81, 0x27) + 
        	raw_string(0x04, 0x01, 0x00, 0x24, 0x22, 0x24, 0x20, 0x24,
			   0x18, 0x24, 0x16, 0x24, 0x14, 0x24, 0x12, 0x24,
			   0x10, 0x24, 0x0e, 0x24, 0x0c, 0x24, 0x0a, 0x24,
			   0x08, 0x24, 0x06, 0x24, 0x04, 0x24, 0x02, 0x04,
			   0x00, 0x04, 0x82, 0x00, 0x02, 0x39, 0x25)  +
        	raw_string(0xa1, 0x08) +
       			raw_string(0x04, 0x06) + 
				"Nessus";

 return data;
}




port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner ) exit(1, "No HTTP banner on port "+port+".");
if ( "IIS" >!< banner ) exit(0, "Server on port "+port+" is not IIS.");


blob = base64(str:gssapi(oid:oid(), spenego:spenego(negTokenInit:negTokenInit(mechType:mechType(), mechListMIC
:mechListMIC()))));



req = string("GET / HTTP/1.1\r\n",
"Authorization: Negotiate ", blob, "\r\n",
"Host: ", get_host_name(), "\r\n\r\n");

r = http_send_recv3(method:"GET", item: "/", port: port, 
  username: "", password: "", add_headers: make_array("Negociate", blob));
# Vulnerable -> WWW-Authenticate: Negotiate xxxxx\r\n
# Not vulnerable -> WWW-Authenticate: Negotiate\r\n
if (egrep(pattern:"WWW-Authenticate: Negotiate [a-zA-Z0-9\+/=]+$", string:r[1]))
{
 security_hole(port);
}
