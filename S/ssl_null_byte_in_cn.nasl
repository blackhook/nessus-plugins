#TRUSTED 313fb1ba6764432425e4889459de4e225e7e46cf2898c653bea0ba841fe3e6ae24d625342aa71ad0e3364c026651b4c927dcd43b55636c97a53cfe56f850405d860d29832d4dfa8e031c65fdfd43517706d13b7c42ac561ed7f856fbcd45312d3b50330640957bdf73ed044994b5429e109029b81112771e0dd78d075f1118bafefa79569c4d3c5b77d0ba74ae9fcf5cc62b3c076c05740dd456c1039ed6f7e3dc87f513489a8ad502d90e1e6c355d53fe8ce53039191c9419e2eaea83d0dac3aad1aabc604d735f7257985599d327015636fefc8888e31d51c141ca172f6fc676e9bfe06388fa4a53e1b0e3a19a4db62a67ce72653056964deae6bbca3432e33b6c2dd20079fd593a074d68ed4f61d36d6f35cf41654d2748deab63de9d097dda627d4de6ce686e1ff8139a3fbdb1fa5a86824056e0ba27623eedd2f375a0e97df2c9dd8a7e9f65bb5f981a815be34155e40be85790fa474b21ec9419fcb401eb8397ed3566aae433c97e60b1750a7a5d1251961ac652073b7596626fd1f162f7bcf388ac069ae2208ac7fa42182accaac6e91ce0d0246d03f9f6de34fc3bba32ad753afa385cef6fbd3a8104c8b322ad7b3f875afad6f457fe31bc0565a7d9a770e485011e3c1df31de17721c3522f3c135b9650d458b4f9ad1764d31397b5b9227a87a6e8742c515199aeb166741aa989df4a4728c7cd54b8ef98d5f1cf38
#
# (C) Tenable Network Security, Inc.
#


# Check if this version of nessusd is too old
if ( NASL_LEVEL < 3208 ) exit(0);


include("compat.inc");

if (description)
{
 script_id(42053);
 script_version("1.12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/26");
 
 script_name(english:"SSL Certificate Null Character Spoofing Weakness");
 script_summary(english:"Determines if the remote SSL/TLS certificate contains a Null");

 script_set_attribute(attribute:"synopsis", value:
"This plugin determines if the remote SSL certificate contains a Null 
character.");
 script_set_attribute(attribute:"description", value:
"The remote host contains an SSL certificate with a common name
containing a Null character (\x00) in it.  This may indicate a
compromise or that a program such as SSLsniff is spoofing the
certificate in order to intercept the traffic via a Man-in-The-Middle
(MiTM) attack. 

Certificates with such characters may exploit a bug contained in many
different web browser and other SSL-related products, in how they
validate the common name of such a certificate.");

 script_set_attribute(attribute:"see_also", value:"https://moxie.org/papers/null-prefix-attacks.pdf");
 script_set_attribute(attribute:"solution", value:
"Recreate the remote SSL certificate.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2009-2020 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencies("ssl_supported_versions.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}

include("global_settings.inc");
include("x509_func.inc");


get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(1, "The host does not appear to have any SSL-based services.");

if (!get_port_state(port)) exit(0, "Port " + port + " is not open.");

cert = get_server_cert(port:port, encoding:"der");
if (isnull(cert)) exit(1, "Failed to read the certificate for the service listening on port "+port+".");

cert = parse_der_cert(cert:cert);
if (isnull(cert)) exit(1, "Failed to parse the certificate from the service listening on port "+port+".");

report = dump_certificate(cert:cert);

line = strstr(report, "Common Name:");
if (isnull(line)) exit(1, "Failed to find the Common Name in the certificate from the service listening on port "+port+".");

eol  = strstr(line, '\n');
if ( isnull(eol) ) exit(1, "Failed to find end-of-line in the certificate from the service listening on port "+port+".");

line -= eol;
real_name = str_replace(string:line, find:'\0x00', replace:'.');
eol = strstr(line, '\x00');
fake_name = line - eol;
fake_name -= "Common Name:";

if ( '\x00' >< line ) security_hole(port:port, extra:'\nThe remote SSL certificate CN was made for :\n\n' + real_name + '\n\nBut it appears to come from :\n\n' + fake_name);
