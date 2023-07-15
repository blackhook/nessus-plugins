#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132725);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/08");

  script_cve_id("CVE-2019-1551");
  script_xref(name:"IAVA", value:"2019-A-0303-S");

  script_name(english:"OpenSSL 1.1.1 < 1.1.1e-dev Procedure Overflow Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a procedure overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.1e-dev. It is, therefore, affected by a
vulnerability as referenced in the 1.1.1e-dev advisory.

  - There is an overflow bug in the x64_64 Montgomery
    squaring procedure used in exponentiation with 512-bit
    moduli. No EC algorithms are affected. Analysis suggests
    that attacks against 2-prime RSA1024, 3-prime RSA1536,
    and DSA1024 as a result of this defect would be very
    difficult to perform and are not believed likely.
    Attacks against DH512 are considered just feasible.
    However, for an attack the target would have to re-use
    the DH512 private key, which is not recommended anyway.
    Also applications directly using the low level API
    BN_mod_exp may be affected if they use BN_FLG_CONSTTIME.
    Fixed in OpenSSL 1.1.1e-dev (Affected 1.1.1-1.1.1d).
    (CVE-2019-1551)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/openssl/openssl/commit/f1c5eea8a817075d31e43f5876993c6710238c98
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83f0f491");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20191206.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.1e-dev or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:"1.1.1e-dev", min:"1.1.1", severity:SECURITY_WARNING);
