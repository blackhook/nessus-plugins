#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(121009);
 script_version("1.9");
 script_cvs_date("Date: 2019/03/27 13:17:50");

 script_name(english:"SSL Certificate Validity - Duration");
 script_summary(english:"Checks SSL certificate validity duration");

 script_set_attribute(
  attribute:'synopsis',
  value:
"The SSL certificate is valid over a time period that is too long."
 );
 script_set_attribute(
  attribute:'description',
  value:
"The CA/Browser Forum has passed a resolution setting the maximum
validity period for SSL/TLS subscriber certificates via ballot 193.

Certificates issued after March 1, 2018 may not be valid longer than
825 days.  Certificates issued after July 1, 2016 through
March 1, 2018 may not be valid longer than 39 months.  Certificates
issued on or before July 1, 2016 may not be valid longer than 60
months.

Long validity periods encourage certificate owners to keep
certificates in production that have vulnerabilities associated
with weak cryptography and that may be out of compliance with other
security guidelines.

Note:  CA/Browser Forum ballot 193 specifies policy based on the
day the certificate was issued.  SSL/TLS certificates do not carry an
issuance date.  This plugin uses a certificate's 'Not Valid Before'
date as a proxy for the date the certificate was issued."
 );
 script_set_attribute(
  attribute:"solution",
  value:
"Replace the SSL certificate with a certificate having a validity
period less than or equal to 825 days."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Certificates that are outdated despite their validity period can have cryptographic and protocol weaknesses.");
 #https://cabforum.org/2017/03/17/ballot-193-825-day-certificate-lifetimes/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c70535d");


 script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"General");

 script_dependencies("ssl_cert_expiry.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("datetime.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

orig_date_of_inception = calendar_to_bn_epoch(year:2016, mon:6, day:30, hour:0, min:0, sec:1);
new_date_of_inception = calendar_to_bn_epoch(year:2018, mon:3, day:1, hour:0, min:0, sec:1);

function more_than_x_months(start, end, x)
{
  var start_human = localtime(bn_raw2dec(start), utc:TRUE);
  var period_end = calendar_to_bn_epoch(year:start_human.year, mon:start_human.mon + x,
    day:start_human.mday, hour:start_human.hour, min:start_human.min,
    sec:start_human.sec);

  return bn_cmp(key1:end, key2:period_end) > 0;
}

ports = get_kb_list("Transport/SSL");

# Get list of ports that use SSL or StartTLS.
if (isnull(ports))
  audit(AUDIT_HOST_NONE, "SSL-based services");

starts = get_kb_list("Transport/SSL/*/valid_start_alt");
ends = get_kb_list("Transport/SSL/*/valid_end_alt");
readable_starts = get_kb_list("Transport/SSL/*/valid_start");
readable_ends = get_kb_list("Transport/SSL/*/valid_end");
sub_certs = get_kb_list("Transport/SSL/*/subscriber_cert");
issuers = get_kb_list("Transport/SSL/*/issuer");
subjects = get_kb_list("Transport/SSL/*/subject");

ports = make_list(ports);
starttls_ports = get_kb_list("*/*/starttls");
foreach key (keys(starttls_ports))
{
  # Extract port from KB item name.
  port = split(key, sep:"/", keep:FALSE);
  port = int(port[1]);

  # Ignore invalid ports.
  if (port < 1 || port > 65535)
    continue;

  ports = add_port_in_list(list:ports, port:port);
}

num_ports = len(ports);

for(i = 0; i < num_ports; i++)
{
  port = ports[i];

  if (!get_port_state(port)) continue;

  key = 'Transport/SSL/' + port + '/';

  if (!sub_certs[key + 'subscriber_cert']) continue;

  readable_valid_start = readable_starts[key + 'valid_start'];
  readable_valid_end = readable_ends[key + 'valid_end'];

  valid_start = starts[key + 'valid_start_alt'];
  valid_end = ends[key + 'valid_end_alt'];
  if (!valid_start) continue;
  if (!valid_end) continue;
  valid_too_long = FALSE;

  epoch_start_validity = bn_hex2raw(valid_start);
  epoch_end_validity = bn_hex2raw(valid_end);

  one_day_in_secs = bn_dec2raw(60 * 60 * 24);
  epochdiff = bn_sub(epoch_end_validity, epoch_start_validity);


  cert_duration_days = int(bn_raw2dec(bn_div(epochdiff, one_day_in_secs)));
  if(bn_mod(epochdiff, one_day_in_secs) > 0)
    cert_duration_days++;

  if(!epoch_start_validity || !epoch_end_validity || !cert_duration_days) continue;

  if(bn_cmp(key1:epoch_start_validity, key2:new_date_of_inception) >= 0)
  {
    if(cert_duration_days > 825) valid_too_long = TRUE;
  }
  else if(bn_cmp(key1:epoch_start_validity, key2:orig_date_of_inception) >= 0)
  {
    valid_too_long = more_than_x_months(start:epoch_start_validity, end:epoch_end_validity, x:39);
  }
  else
  {
    valid_too_long = more_than_x_months(start:epoch_start_validity, end:epoch_end_validity, x:60);
  }

  if(valid_too_long)
  {
    if (report_verbosity > 0)
    {
      issuer = issuers[key + 'issuer'];
      subject = subjects[key + 'subject'];

      report =
        '\n' + 'The SSL certificate has a valid duration of ' +  cert_duration_days + ' days.' +
        '\n' +
        '\n  Subject          : ' + subject +
        '\n  Issuer           : ' + issuer +
        '\n  Not valid before : ' + readable_valid_start +
        '\n  Not valid after  : ' + readable_valid_end + '\n';

      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
