#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157231);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/29");

  script_cve_id("CVE-2021-4160");

  script_name(english:"OpenSSL 1.0.2 < 1.0.2zc-dev Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.2zc-dev. It is, therefore, affected by a
vulnerability as referenced in the 1.0.2zc-dev advisory.

  - There is a carry propagation bug in the MIPS32 and MIPS64 squaring procedure. Many EC algorithms are
    affected, including some of the TLS 1.3 default curves. Impact was not analyzed in detail, because the
    pre-requisites for attack are considered unlikely and include reusing private keys. Analysis suggests that
    attacks against RSA and DSA as a result of this defect would be very difficult to perform and are not
    believed likely. Attacks against DH are considered just feasible (although very difficult) because most of
    the work necessary to deduce information about a private key may be performed offline. The amount of
    resources required for such an attack would be significant. However, for an attack on TLS to be
    meaningful, the server would have to share the DH private key among multiple clients, which is no longer
    an option since CVE-2016-0701. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0.0. It was
    addressed in the releases of 1.1.1m and 3.0.1 on the 15th of December 2021. For the 1.0.2 release it is
    addressed in git commit 6fc1aaaf3 that is available to premium support customers only. It will be made
    available in 1.0.2zc when it is released. The issue only affects OpenSSL on MIPS platforms. Fixed in
    OpenSSL 3.0.1 (Affected 3.0.0). Fixed in OpenSSL 1.1.1m (Affected 1.1.1-1.1.1l). Fixed in OpenSSL 1.0.2zc-
    dev (Affected 1.0.2-1.0.2zb). (CVE-2021-4160)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/openssl/openssl/commit/6fc1aaaf303185aa5e483e06bdfae16daa9193a7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acbd2764");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20220128.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2zc-dev or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include('openssl_version.inc');

openssl_check_version(fixed:'1.0.2zc-dev', min:'1.0.2', severity:SECURITY_WARNING);
