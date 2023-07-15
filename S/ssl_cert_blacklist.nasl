#TRUSTED 9a9069d176f92b7e632e64ea571748de19797fc626667899f2595ea7dbc417f86060bdd6f9d36407ce94405c8697d9b60f983bd83344e81ea552acd776bfec58d7da7de69bb43dfe333764a7620d020212339b8e5cdf66dd99d0eea705f93b08e7c8f166c6fe1e460537ee13fbcec52bf346a2e8bf14bc1eeed2ae7e78908e4417d5c79c68ac136cd9806174371c9f962a5525e34737bdd644da5b3d15c6606dae7c321f7d9fa1659c0c99da9c55d4eb5e969addaf1e0ae96914d4155d219ccd6bb832188ebfbe79e367ee540562bfa3b9f03be7d4dc4381ace0447df8fcc5a107909b3a5d8c3b2d10186c4feb8d96387627a8c47ebfef1b92ae99b34de24c52e9867d76628c02bf3261f0abbe1793b8bed12a3c5d9a28ef55671afefb8a25151e64d5eb7d69fd2c48346a9791e6cf153b8a1648115657c95f62371251713e1b2bdb68ed2a56f4e707fc936c0d8c929d2f415c343fdafdc2e99d70bff1d9b9ccdb38e72782173b02c50355e1425df70adad66f2f8acef901282b676347e922b93e3327583b48ee005fbe990b130c8596a151991d7737bc1a543c9d4d7af0d5c2451d9a49baa94842807688ddfcb4260bd8ef66dd8cb93d960167d52437dac686bb241a5afdeac4c693733bf4883a5ed1d577d5a494d1980b60caf93d29760478a88769f135fd727a2a87de6dc7a2199e2eca383a31ad2f8159301c92191a4995
#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3208) exit(0);


include("compat.inc");


if (description)
{
  script_id(52963);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/26");

  script_name(english:"Blacklisted SSL Certificate");
  script_summary(english:"Compare an SSL certificate's serial number to a blacklist.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service uses a compromised SSL certificate.");
  script_set_attribute(attribute:"description", value:
"The remote service uses an SSL certificate that is either fraudulent,
no longer secure due to leaked or compromised private keys, or was
issued from a certificate authority that is considered to be
untrustworthy.");
  # https://blog.torproject.org/detecting-certificate-authority-compromises-and-web-browser-collusion
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14606051");
  script_set_attribute(
    attribute:"solution", 
    value:"Purchase a new SSL certificate from a trusted certificate authority."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2020 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("global_settings.inc");
include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, "The host does not appear to have any SSL-based services.");

# Specify what's blacklisted.
#
# nb: certs signed by DigiNotar are flagged via a separate plugin, 
#     ssl_diginotar.nasl.
#
# nb: each cert is checked against elements of the 'fingerprints',
#     'issuer_rdns', and 'serial_nums' arrays, and each element in
#     turn is a list. The cert is considered blacklisted if it 
#     matches one of the list items for each of the arrays defined
#     for a particular blacklist.
i = 0;
label           = make_array();    # nb: each element is an arbitrary label displayed in plugin output
links           = make_array();    # nb: each is a list of links / text
fingerprints    = make_array();    # nb: each is an SHA1 fingerprint; eg, "F7:98:D3:C3:55:7D:20:68:02:26:0C:51:CE:F6:E1:CE:32:DC:F8:A4"
issuer_rdns     = make_array();    # nb: each is the issuer's RDN to match on.
serial_nums     = make_array();    # nb: each is a list of serial numbers to match on.

label[i]        = "Comodo / USERTRUST Fraud Incident, March 2011";
links[i]        = make_list(
                    "http://www.comodo.com/Comodo-Fraud-Incident-2011-03-23.html"
                  );
issuer_rdns[i]  = make_list(
                    "CN=UTN-USERFirst-Hardware,OU=http://www.usertrust.com,O=The USERTRUST Network,L=Salt Lake City,ST=UT,C=US"
                  );
serial_nums[i]  = make_list(
                    "047ECBE9FCA55F7BD09EAE36E10CAE1E",
                    "00F5C86AF36162F13A64F54F6DC9587C06",
                    "00D7558FDAF5F1105BB213282B707729A3",
                    "392A434F0E07DF1F8AA305DE34E0C229",
                    "3E75CED46B693021218830AE86A82A71",
                    "00E9028B9578E415DC1A710A2B88154447",
                    "009239D5348F40D1695A745470E1F23F43",
                    "00B0B7133ED096F9B56FAE91C874BD3AC0",
                    "00D8F35F4EB7872B2DAB0692E315382FB0"
                  );
i++;

# nb: Entrust's bulletin talks only about 22 certs with weak 512-bit
#     RSA keys and missing certificate extensions, but Mozilla and 
#     Microsoft are blacklisting trust in the CA completely.  We're 
#     following their lead here. 
label[i]        = "DigiCert Sdn. Bhd Intermediate Certificate Authority trust revocation, November 2011";
links[i]        = make_list(
                    "http://www.entrust.net/advisories/malaysia.htm",
                    "http://blog.mozilla.com/security/2011/11/03/revoking-trust-in-digicert-sdn-bhd-intermediate-certificate-authority/"
                  );
issuer_rdns[i]  = make_list(
                    "C=MY,O=Digicert Sdn. Bhd.,OU=457608-K,CN=Digisign Server ID (Enrich)",
                    "C=MY,O=Digicert Sdn. Bhd.,OU=457608-K,CN=Digisign Server ID - (Enrich)"
                  );
i++;

label[i]        = "drmlocal.cisco.com certificate private key leak 2017";
links[i]        = make_list(
                    "https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/T6emeoE-lCU"
                  );
issuer_rdns[i]  = make_list(
                    "C=US, O=HydrantID (Avalanche Cloud Corporation), CN=HydrantID SSL ICA G2"
                  );
serial_nums[i]  = make_list("66170CE2EC8B7D88B4E2EB732E738FE3A67CF672");

i++;

n = i;

# Loop over each port.
foreach port (ports)
{
  if (!get_port_state(port)) continue;

  # Get its cert.
  cert = get_server_cert(port:port, encoding:"der");
  if (isnull(cert)) exit(1, "Failed to read the certificate for the service listening on port "+port+".");

  # Calculate its SHA1 fingerprint.
  sha1 = toupper(hexstr(SHA1(cert)));
  digest = "";
  for (i=0; i<strlen(sha1); i+=2)
    digest = strcat(digest, sha1[i], sha1[i+1], ":");
  digest = substr(digest, 0, strlen(digest) - 2);

  # Extract the issuer and serial number.
  cert = parse_der_cert(cert:cert);
  if (isnull(cert)) exit(1, "Failed to parse the SSL certificate associated with the service on port "+port+".");

  tbs = cert["tbsCertificate"];
  issuer_seq = tbs["issuer"];

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

    if (attr) issuer += ',' + attr + '=' + seq[1];
  }
  if (issuer) issuer = substr(issuer, 1);

  serial = hex_buf(buf:tbs["serialNumber"], space:0);
  serial = str_replace(find:" ", replace:"", string:serial);

  # Check it against blacklisted elements.
  for (i=0; i<n; i++)
  {
    info = make_array();

    if (fingerprints[i])
    {
      matched = FALSE;
      foreach fingerprint (fingerprints[i])
        if (fingerprint == digest)
        {
          matched = TRUE;
          break;
        }

      if (!matched) continue;
      else info['SHA1 fingerprint'] = digest;
    }

    if (issuer_rdns[i])
    {
      matched = FALSE;
      foreach issuer_rdn (issuer_rdns[i])
        if (issuer_rdn == issuer)
        {
          matched = TRUE;
          break;
        }

      if (!matched) continue;
      else info['Issuer'] = issuer;
    }

    if (serial_nums[i])
    {
      matched = FALSE;
      foreach serial_num (serial_nums[i])
        if (serial_num == serial)
        {
          matched = TRUE;
          break;
        }

      if (!matched) continue;
      else
      {
        serial = ereg_replace(pattern:"(..)", replace:"\1:", string:serial);
        serial = substr(serial, 0, strlen(serial)-2);
        info['Serial number'] = serial;
      }
    }

    if (max_index(keys(info)))
    {
      if (report_verbosity > 0)
      {
        if (label[i]) info['Label'] = label[i];
        if (links[i]) info['Information links'] = links[i];

        max_key_len = 0;
        foreach key (keys(info))
        {
          if (strlen(key) > max_key_len) max_key_len = strlen(key);
        }

        report = '';
        foreach key (make_list('Label', 'Information links'))
        {
          if (!info[key]) continue;
          if (key == 'Label') val = info[key];
          else val = join(info[key], sep:'\n  '+crap(data:' ', length:max_key_len+3));

          report += '\n  ' + key + crap(data:" ", length:max_key_len-strlen(key)) + ' : ' + val;
        }
        foreach key (sort(keys(info)))
        {
          if (key == 'Label' || key == 'Information links') continue;
          val = info[key];
          report += '\n  ' + key + crap(data:" ", length:max_key_len-strlen(key)) + ' : ' + val;
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      # We're finished checking the blacklists if we found a match.
      break;
    }
  }
}
