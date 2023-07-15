#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(10723);
  script_version("1.38");

  script_name(english:"LDAP Server NULL Bind Connection Information Disclosure");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote LDAP server allows anonymous access."
  );
  script_set_attribute( attribute:"description",  value:
"The LDAP server on the remote host is currently configured such that a
user can connect to it without authentication - via a 'NULL BIND' -
and query it for information.  Although the queries that are allowed
are likely to be fairly restricted, this may result in disclosure of
information that an attacker could find useful.

This plugin does not identify servers that use LDAP v3 since
anonymous access -- a 'NULL BIND' -- is required by that version
of the protocol.");
  script_set_attribute( attribute:"solution",  value:"Configure the service to disallow NULL BINDs."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on potential information disclosure.");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/03/15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_summary(english:"Check for LDAP null bind");

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2001-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("der_funcs.inc");
include("ldap_func.inc");

port = get_kb_item("Services/ldap");
if (!port) port = 389;
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");

ldap_init(socket:soc);

# nb: LDAP v3 requires anonymous access to the RootDSE so 
#     using that would ensure the bind works.
data = 
	der_encode_int(i:2)                 +  # LDAP version
	der_encode_octet_string(string:"")  +  # name
	der_encode(tag:LDAP_AUTHENTICATION_TAG, data:"");

bind = ldap_request(code:LDAP_BIND_REQUEST, data:data);
ret = ldap_request_sendrecv(data:bind);

if (isnull(ret) || ret[0] != LDAP_BIND_RESPONSE)
  exit(1, "Unexpected reponse to the bind request on port " + port);

data = ldap_parse_bind_response(data:ret[1]);
if (isnull(data) || data[0] != 0)
{
  close(soc);
  exit(1, "ldap_parse_bind_response() failed for port " + port);
}

# If the NULL bind worked, check to see whether or not version 3 is being used
search = ldap_search_request(object:"", filter:"objectclass", scope:"", attributes:"supportedLDAPVersion");
ret = ldap_request_sendrecv(data:search);
close(soc);

if (isnull(ret))
{
  exit(1, "The service didn't respond to the search request on port " + port);
}
# this is how ldap v2 responds
else if (ret[0] == LDAP_SEARCH_RES_DONE)
{
  res = ldap_parse_bind_response(data:ret[1]);
  if(isnull(res))
    exit(1, 'Failed to parse a SearchResultDone message.');

  # unwillingToPerform
  # i.e., server configured to reject unauthenticated requests
  if(res[0] == 53)
    exit(0, 'The service on port '+port+' returned a SearchResultDone message with result code '+ res[0] + '.');

  security_warning(port);
  exit(0);
}
# ldap v3 should respond with this code
else if (ret[0] != LDAP_SEARCH_RES_ENTRY)
{
  exit(1, "Unexpected response to the search request on port " + port);
}

# at this point we know we're looking at ldap v3 based on the
# behavior alone, but we'll check for the response value just
# for the sake of completeness
data = ldap_parse_search_entry(data:ret[1]);
if (isnull(data) || data[0][0] != "supportedLDAPVersion")
  exit(1, "ldap_parse_search_entry() failed for port " + port);

foreach ver (data[0][1])
{
  if (ver == 3)
    exit(0, 'The service on port '+port+' uses LDAP v3 and therefore is not affected.');
}

exit(0, 'The service on port '+port+' uses LDAP v3 and therefore is not affected.');
