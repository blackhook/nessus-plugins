#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93112);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-2183");
  script_bugtraq_id(92630);

  script_name(english:"OpenSSL < 1.0.2i Default Weak 64-bit Block Cipher (SWEET32)");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The service running on the remote host uses a weak encryption block
cipher by default.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSL running on the remote
host is prior to 1.0.2i. It is, therefore, affected by a vulnerability,
known as SWEET32, in the 3DES and Blowfish algorithms due to the use
of weak 64-bit block ciphers by default. A man-in-the-middle attacker
who has sufficient resources can exploit this vulnerability, via a
'birthday' attack, to detect a collision that leaks the XOR between
the fixed secret and a known plaintext, allowing the disclosure of the
secret text, such as secure HTTPS cookies, and possibly resulting in
the hijacking of an authenticated session.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2i or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2183");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.2i', min:"1.0.1", severity:SECURITY_WARNING);
