#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104409);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-3735", "CVE-2017-3736");
  script_bugtraq_id(100515);

  script_name(english:"OpenSSL 1.1.0 < 1.1.0g RSA/DSA Unspecified Carry Issue");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"A service running on the remote host is affected by an unspecified 
carry vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSL running on the remote
host is 1.1.0 prior to 1.1.0g. It is, therefore, affected by an 
unspecified carry vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20171102.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0g or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.1.0g', min:"1.1.0", severity:SECURITY_WARNING);

