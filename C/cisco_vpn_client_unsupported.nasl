#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64437);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_cve_id("CVE-2012-5429");
  script_bugtraq_id(57483);

  script_xref(name:"IAVA", value:"0001-A-0523");

  script_name(english:"Cisco VPN Client Unsupported");
  script_summary(english:"Checks for Cisco VPN Client");

  script_set_attribute(attribute:"synopsis", value:
"The VPN client installed on the remote Windows host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"The Cisco VPN client installed on the remote host is no longer
supported and is potentially affected by a denial of service
vulnerability as well as other unacknowledged security issues. As of
July 30, 2012, the vendor no longer provides security fixes for the
installed product.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.cisco.com/c/en/us/products/collateral/security/vpn-client/end_of_life_c51-680819.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1f130e9");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=27926
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0607e33c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5429");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:vpn_client");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vpn_client_detect.nasl");
  script_require_keys("SMB/CiscoVPNClient/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

ver  = get_kb_item_or_exit("SMB/CiscoVPNClient/Version");
path = get_kb_item_or_exit("SMB/CiscoVPNClient/Path");
port = get_kb_item("SMB/transport");

register_unsupported_product(product_name:"Cisco VPN Client",
                             version:ver, cpe_base:"cisco:vpn_client");

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver  +
    '\n  Solution          : Upgrade to Cisco AnyConnect Secure Mobility Client' +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
