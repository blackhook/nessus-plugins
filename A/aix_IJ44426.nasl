##
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory22.asc.
#'
# @DEPRECATED@
#
# Disabled on 2023/02/08. Erroneous duplicate of aix_IJ44425.nasl.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(169318);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2022-2795", "CVE-2022-3080", "CVE-2022-38177", "CVE-2022-38178");

  script_name(english:"AIX 7.2 TL 5 : bind (IJ44426) (deprecated)");
  script_summary(english:"Check for APAR IJ44426");

  script_set_attribute(
    attribute:"synopsis",
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-38178
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-38178 ISC BIND
is vulnerable to a denial of service, caused by a memory leak in the
DNSSEC verification code for the EdDSA algorithm. By spoofing the
target resolver with responses that have a malformed EdDSA signature,
a remote attacker could exploit this vulnerability to cause named to
crash. ISC BIND is vulnerable to a denial of service, caused by an
error when stale cache and stale answers are enabled, option
stale-answer-client-timeout is set to 0 and there is a stale CNAME in
the cache for an incoming query. By sending a specially-crafted
request, a remote attacker could exploit this vulnerability to cause
named to crash. ISC BIND is vulnerable to a denial of service, caused
by a small memory leak in the DNSSEC verification code for the ECDSA
algorithm. By spoofing the target resolver with responses that have a
malformed ECDSA signature, a remote attacker could exploit this
vulnerability to cause named to crash. ISC BIND is vulnerable to a
denial of service, caused by a flaw in resolver code. By flooding the
target resolver with queries, a remote attacker could exploit this
vulnerability to severely degrade the resolver's performance,
effectively denying legitimate clients access to the DNS resolution
service.

Deprecated. Edge case for unusual circumstances that was incorrectly
generated. May be replaced in the future."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/bind_advisory22.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38178");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"AIX Local Security Checks");

  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}
exit(0, 'This plugin has been deprecated. Use aix_IJ44425.nasl (plugin ID 169317) instead.');


