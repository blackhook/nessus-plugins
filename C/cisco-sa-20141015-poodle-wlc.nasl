#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(79690);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141015-poodle");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur27551");

  script_name(english:"Cisco Wireless LAN Controllers 5500 Series (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security update.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Wireless LAN Controller (WLC) is affected by an
information disclosure vulnerability known as POODLE. The
vulnerability is due to the way SSL 3.0 handles padding bytes when
decrypting messages encrypted using block ciphers in cipher block
chaining (CBC) mode. MitM attackers can decrypt a selected byte of a
cipher text in as few as 256 tries if they are able to force a victim
application to repeatedly send the same data over newly created SSL
3.0 connections.");
  # https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20141015-poodle.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f86217b4");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug CSCur27551 or contact
the vendor regarding patch options.

Alternatively, to mitigate this issue, FIPS mode can be enabled with
the following command 'config switchconfig fips-prerequisite enable'.
Note that this change can affect the operation of other features.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:TF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/WLC/Version");
model = get_kb_item_or_exit("Host/Cisco/WLC/Model");
port = get_kb_item_or_exit("Host/Cisco/WLC/Port");

# Only 5500 series
if (model !~ "(^|[^0-9])55\d\d($|[^0-9])") audit(AUDIT_HOST_NOT, "Cisco 5500 Series Wireless Controller");

######################
# Known Affected :
# 7.0(250.0)
# 7.4(121.0)
# 7.6(130.0)
# 8.0(100.0)
######################
# Known Fixed :
# 7.0(241.14)
# 7.5(102.28)
# 7.6(130.13)
# 8.0(102.37)
# 8.1(10.51)
######################

fixed_version = "";
if (version == "7.0.250.0") fixed_version = "See solution.";
else if (version == "7.4.121.0") fixed_version = "7.5.102.28";
else if (version == "7.6.130.0") fixed_version = "7.6.130.13";
else if (version == "8.0.100.0") fixed_version = "8.0.102.37 / 8.1.10.51";
else audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Model             : ' + model +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

