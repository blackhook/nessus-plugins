#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(81782);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66363, 66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"IBM Rational ClearQuest 7.1.1.x / 7.1.2.x < 7.1.2.13.01 / 8.0.0.x < 8.0.0.10.01 / 8.0.1.x < 8.0.1.3.01 OpenSSL Library Multiple Vulnerabilities (credentialed check) (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Rational ClearQuest 7.1.1.x /
7.1.2.x prior to 7.1.2.13.01 / 8.0.0.x prior to 8.0.0.10.01 / 8.0.1.x
prior to 8.0.1.3.01 installed. It is, therefore, potentially affected
by multiple vulnerabilities in the OpenSSL library :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    allows nonce disclosure via the 'FLUSH+RELOAD' cache
    side-channel attack. (CVE-2014-0076)

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS heartbeat
    extensions that allows an attacker to obtain sensitive
    information such as primary key material, secondary key
    material, and other protected content. Note that this
    error only affects versions of ClearQuest later than
    7.1.2. (CVE-2014-0160)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21670905");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21666414");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational ClearQuest 7.1.2.13 Interim Fix 01
(7.1.2.13.01) / 8.0.0.10 Interim Fix 01 (8.0.0.10.01) / 8.0.1.3
Interim Fix 01 (8.0.1.3.01) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_rational_clearquest_installed.nasl");
  script_require_keys("installed_sw/IBM Rational ClearQuest", "Settings/ParanoidReport");

  exit(0);
}

include('ibm_rational_clearquest_version.inc');

rational_clearquest_check_version(
  fixes:make_nested_list(
    # Versions earlier than 7.1.1 are not affected
    make_array("Min", "7.1.1", "Fix UI", "7.1.2.13.01", "Fix", "7.1213.1.140"),
    make_array("Min", "8.0.0", "Fix UI", "8.0.0.10.01", "Fix", "8.10.1.723"),
    make_array("Min", "8.0.1", "Fix UI", "8.0.1.3.01",  "Fix", "8.103.1.422")),
  severity:SECURITY_WARNING,
  paranoid:TRUE # only certain configurations using OpenSSL w/ ECDSA
);
