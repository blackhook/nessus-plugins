#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112119);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-0732", "CVE-2018-0737");
  script_bugtraq_id(103766, 104442);

  script_name(english:"OpenSSL 1.0.x < 1.0.2p Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"A service running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSL running on the remote
host is 1.0.x prior to 1.0.2p. It is, therefore, affected by a denial
of service vulnerability and a cache timing side channel
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20180612.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20180416.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2p or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.2p', min:"1.0.2", severity:SECURITY_WARNING);

