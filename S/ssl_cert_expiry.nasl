#TRUSTED 0d1f95035c423e884e781509754f9f363f15aca698fa5597ba5090fa97da3cbfb81d78ab783551049cf91f54c232022a12a029ddbc25c5a72817f7db889b2ed62a08df2827ca6747e06199ebac647ca22780bd50148b05e5ba8d508ab8456806b964db80625ac5b61a25d6640013413932c2c6d28221bb594ea000e3e217105970d0ae0bf7f52d3dff24ee82392a74136d9eeb05d314385f12a1311e4f12fe808c278d5a420dc4798a06f9b2d752b855ae2ebe1a8784cb8ca214b3ebfcf87916add65649c51b0f9f47eca6275896a669e1d85e822e6e4646551c8b30eeb91fb367ad902e2bae50e6a1cd7b7c0ec385470cb1cfa3947632e4aaf224779d123f3e9bd1721908331ff8b5e43130bbe1ee6e01365169735d1a02b3220a8851dfdaeda9aaca67386ded30eab6afc0579b6882f886e1df99036e7155e0b329c9a0cb4eeef19e957c8b134ee4ee9a77d77069b6ceaf6d135b9de97d0aeaff39dd485d6966f546f711f5a1995ef7aa98b2d37b7bfd171a7a3293d443e0bc707d89f68d1cf2e65fe8a61002ae57a554136aa792d9695dcf8ed8476032080cc19c9cbee1a8a9d1b8bf16be5b5cdeb2e4e0da6b812a5539443d2348531b8ebaf0b8e90f6172be7766fd5ffe8cfc1b6e7b9892c5ec5e3af2a3fe37deb7636ec1f8ff4cd8674afc0a9159cd9703e6e81697bbc504a2233f40b197412d5a4f2ad06677ff4aacd4
#
# @PREFERENCES@
#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
# Changes by Tenable :
# - Updated to use compat.inc, made report severity consistent (11/23/09)
# - Added CVSS score, KBs. (11/23/09)
# - Signed. (10/18/2013)
# - Made expiration warning period user-configurable. (05/12/15)
# - Added rsync. (2016/01/07)

if ( ! defined_func("localtime") ) exit(0);

include("compat.inc");

if (description)
{
  script_id(15901);
  script_version("1.50");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_name(english:"SSL Certificate Expiry");
  script_summary(english:"Checks the SSL certificate expiry.");

  script_set_attribute(attribute:"synopsis", value:
"The remote server's SSL certificate has already expired.");
  script_set_attribute(attribute:"description", value:
"This plugin checks expiry dates of certificates associated with SSL-
enabled services on the target and reports whether any have already
expired.");
  script_set_attribute(attribute:"solution", value:
"Purchase or generate a new SSL certificate to replace the existing
one.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Expired certificates cannot be validated.");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2004-2021 George A. Theall");

  script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");

  script_add_preference(name:"Identify certificates that expire within x days", type:"entry", value:"60");

  exit(0);
}

include("ftp_func.inc");
include("global_settings.inc");
include("datetime.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("x509_func.inc");
include("audit.inc");
include("rsync.inc");

# How far (in days) to warn of certificate expiry.
# Default to 60, and allow the user to customize as long as a non-null, non-zero int is provided
lookahead = 60;
pref = script_get_preference("Identify certificates that expire within x days");
if (pref =~ "^\d+$")
{
  pref = int(pref);
  if (pref > 0)
    lookahead = pref;
}

set_kb_item(name:'SSL/settings/future_warning_days', value:lookahead);

# This function converts a date expressed as:
#   Year(4)|Month(2)|Day(2)|Hour(2)|Min(2)|Sec(2)
# and returns it in a more human-friendly format.
function x509time_to_gtime(x509time) {
  local_var gtime, i, mm, mon, mons, parts, year;
  mons = "JanFebMarAprMayJunJulAugSepOctNovDec";

  if (x509time && x509time =~ "^[0-9]{14}Z?$") {
    parts[0] = substr(x509time, 0, 3);
    for (i=1; i<= 6; ++i) {
      parts[i] = substr(x509time, 2+i*2, 2+i*2+1);
    }

    year = int(parts[0]);

    mm = int(parts[1]);
    if (mm >= 1 && mm <= 12) {
      --mm;
      mon = substr(mons, mm*3, mm*3+2);
    }
    else {
      mon = "unk";
    }
    parts[2] = ereg_replace(string:parts[2], pattern:"^0", replace:" ");

    gtime = mon + " " +
      parts[2] + " " +
      parts[3] + ":" + parts[4] + ":" + parts[5] + " " +
      year + " GMT";
  }
  return gtime;
}


function x509time_to_bn_epoch(x509time)
{
  local_var gtime, i, mon, parts, year, day, hour, min, sec;

  if (x509time && x509time =~ "^[0-9]{14}Z?$")
  {
    parts[0] = substr(x509time, 0, 3);
    for (i=1; i<= 6; ++i) {
      parts[i] = substr(x509time, 2+i*2, 2+i*2+1);
    }

    year = int(parts[0]);
    mon = int(parts[1]);
    day = int(parts[2]);
    hour = int(parts[3]);
    min = int(parts[4]);
    sec = int(parts[5]);

    gtime = calendar_to_bn_epoch(year:year, mon:mon, day:day, hour:hour, min:min, sec:sec);
  }

  return gtime;
}


if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

# Find out if the port is open.
if(pp_info["proto"] == 'tls')
  cert = get_server_cert(port:port, encoding:"der", dtls:FALSE);
else if(pp_info["proto"] == 'dtls')
  cert = get_server_cert(port:port, encoding:"der", dtls:TRUE);
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

if (isnull(cert))
  exit(1, "Failed to read the certificate for the service listening on " + pp_info["l4_proto"] + " port " + port + ".");


# nb: maybe someday I'll actually *parse* ASN.1.
v = stridx(cert, raw_string(0x30, 0x1e, 0x17, 0x0d));
if (v >= 0) {
  v += 4;
  valid_start = substr(cert, v, v+11);
  v += 15;
  valid_end = substr(cert, v, v+11);

  if (valid_start =~ "^[0-9]{12}$" && valid_end =~ "^[0-9]{12}$") {
    # nb: YY >= 50 => YYYY = 19YY per RFC 3280 (4.1.2.5.1)
    if (int(substr(valid_start, 0, 1)) >= 50) valid_start = "19" + valid_start;
    else valid_start = "20" + valid_start;

    if (int(substr(valid_end, 0, 1)) >= 50) valid_end = "19" + valid_end;
    else valid_end = "20" + valid_end;

    # Get dates, expressed in UTC, for checking certs.
    # - right now.
    tm = localtime(unixtime(), utc:TRUE);
    now = string(tm["year"]);
    foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
      if (tm[field] < 10) now += "0";
      now += tm[field];
    }
    # - 'lookahead' days in the future.
    tm = localtime(unixtime() + lookahead*24*60*60, utc:TRUE);
    future = string(tm["year"]);
    foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
      if (tm[field] < 10) future += "0";
      future += tm[field];
    }
    debug_print("now:    ", now, ".");
    debug_print("future: ", future, ".");

    valid_start_alt = x509time_to_gtime(x509time:valid_start);
    valid_end_alt = x509time_to_gtime(x509time:valid_end);
    debug_print("valid not before: ", valid_start_alt, " (", valid_start, "Z).");
    debug_print("valid not after:  ", valid_end_alt,   " (", valid_end, "Z).");

    key = 'Transport/SSL/' + port + '/';
    replace_kb_item(name:key + 'valid_end', value:valid_end_alt);
    replace_kb_item(name:key + 'valid_start', value:valid_start_alt);
    replace_kb_item(name:key + 'valid_end_alt', value:hexstr(x509time_to_bn_epoch(x509time:valid_end)));
    replace_kb_item(name:key + 'valid_start_alt', value:hexstr(x509time_to_bn_epoch(x509time:valid_start)));

    debug_print("The SSL certificate on port ", port, " is valid between ", valid_start_alt, " and ", valid_end_alt, ".", level:1);

    # Extract the issuer / subject.
    cert2 = parse_der_cert(cert:cert);
    if (isnull(cert2))
      exit(1, "Failed to parse the SSL certificate associated with the service on " + pp_info["l4_proto"] + " port " + port + ".");

    tbs = cert2["tbsCertificate"];
    if(is_subscriber_cert(tbs))
      set_kb_item(name:key + 'subscriber_cert', value:1);

    issuer_seq = tbs["issuer"];
    subject_seq = tbs["subject"];

    issuer = '';
    foreach seq (issuer_seq)
    {
      o = oid_name[seq[0]];
      if (isnull(o)) continue;

      attr = "";
      if (o == "Common Name") attr = "CN";
      else if (o == "Surname") attr = "SN";
      else if (o == "Country") attr = "C";
      else if (o == "Locality") attr = "L";
      else if (o == "State/Province") attr = "ST";
      else if (o == "Street") attr = "street";
      else if (o == "Organization") attr = "O";
      else if (o == "Organization Unit") attr = "OU";
      else if (o == "Email Address") attr = "emailAddress";

      if (attr) issuer += ', ' + attr + '=' + seq[1];
    }
    if (issuer) issuer = substr(issuer, 2);
    else issuer = 'n/a';

    subject = '';
    foreach seq (subject_seq)
    {
      o = oid_name[seq[0]];
      if (isnull(o)) continue;

      attr = "";
      if (o == "Common Name") attr = "CN";
      else if (o == "Surname") attr = "SN";
      else if (o == "Country") attr = "C";
      else if (o == "Locality") attr = "L";
      else if (o == "State/Province") attr = "ST";
      else if (o == "Street") attr = "street";
      else if (o == "Organization") attr = "O";
      else if (o == "Organization Unit") attr = "OU";
      else if (o == "Email Address") attr = "emailAddress";

      if (attr) subject += ', ' + attr + '=' + seq[1];
    }
    if (subject) subject = substr(subject, 2);
    else subject = 'n/a';

    replace_kb_item(name:key + 'issuer', value:issuer);
    replace_kb_item(name:key + 'subject', value:subject);

    if (valid_start > now)
    {
      replace_kb_item(name:key + 'future_validity_date', value:valid_start_alt);
    }
    else if (valid_end < now)
    {
      report =
        '\n' + 'The SSL certificate has already expired :' +
        '\n' +
        '\n  Subject          : ' + subject +
        '\n  Issuer           : ' + issuer +
        '\n  Not valid before : ' + valid_start_alt +
        '\n  Not valid after  : ' + valid_end_alt + '\n';
      security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_WARNING);

      replace_kb_item(name:key + 'expired_cert', value:TRUE);
    }
    else if (valid_end < future)
    {
      replace_kb_item(name:key + 'days_to_expire', value:lookahead);
      replace_kb_item(name:key + 'future_expiry_date', value:valid_end_alt);
    }
  }
}
