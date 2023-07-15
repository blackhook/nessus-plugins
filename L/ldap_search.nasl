#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(25701);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/28");

  script_name(english:"LDAP Crafted Search Request Server Information Disclosure");
  script_summary(english:"Retrieves LDAP Base object information");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to discover information about the remote LDAP server.");
  script_set_attribute(attribute:"description", value:
"By sending a search request with a filter set to 'objectClass=*', it
is possible to extract information about the remote LDAP server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("der_funcs.inc");
include("ldap_func.inc");

port =  get_service(svc: "ldap", default: 389, exit_on_fail:TRUE);
report = NULL;

soc = open_sock_tcp(port);
if (! soc) exit(1, "Connection refused on port "+port+".");

ldap_init(socket:soc);
search = ldap_search_request(object:"", filter:"objectClass", attributes:"namingContexts");
ret = ldap_request_sendrecv(data:search);
if (!isnull(ret) && ret[0] == LDAP_SEARCH_RES_ENTRY)
{
 data = ldap_parse_search_entry(data:ret[1]);
 foreach item (data)
 {
 if ( item[0] == "namingcontexts" ) item[0] = "namingContexts";
 report += "[+]-" + item[0] + ':\n';
 foreach value (item[1])
 {
   val = value;
   report += "   |  " + value + '\n';
   if (item[0] == 'namingContexts' && val)
     set_kb_item(name:"LDAP/" + port + "/" + item[0], value:val);
 }
 }
}
close(soc);

soc = open_sock_tcp(port);
if ( soc )
{
 ldap_init(socket:soc);
 search =
        der_encode_octet_string (string:"") +
        der_encode_enumerated(e:"") +
        der_encode_enumerated(e:0) +
        der_encode_int(i:0) +
        der_encode_int(i:0) +
        der_encode_boolean(b:FALSE) +
        der_encode_filter(filter:"objectclass") +
        der_encode_list(list:"");
 search = ldap_request(code:LDAP_SEARCH_REQUEST, data:search);
 ret = ldap_request_sendrecv(data:search);
 if (!isnull(ret) && ret[0] == LDAP_SEARCH_RES_ENTRY)
 {
  data = ldap_parse_search_entry(data:ret[1]);
  if (!isnull(data))
  {
   foreach item (data)
   {
    report += "[+]-" + item[0] + ':\n';
    foreach value (item[1])
     report += "   |  " + value + '\n';

    if (item[0] == "vendorversion") item[0] = "vendorVersion";
    else if (item[0] == "vendorname") item[0] = "vendorName";

    if (item[0] == "vendorVersion" || item[0] == "vendorName" || item[0] == "dxServerVersion")
    {
     val = item[1];
     val = val[0];
     if (val)
      set_kb_item(name:"LDAP/" + port + "/" + item[0], value:val);
    }
   }
  }
 }
 close(soc);
}


if (strlen(report) > 0)
{
 security_note(port:port, extra:report);
}
