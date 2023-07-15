#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2678-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150309);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/09");

  script_cve_id("CVE-2020-26247");

  script_name(english:"Debian DLA-2678-1 : ruby-nokogiri security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An XXE vulnerability was found in Nokogiri, a Rubygem providing HTML,
XML, SAX, and Reader parsers with XPath and CSS selector support.

XML Schemas parsed by Nokogiri::XML::Schema were trusted by default,
allowing external resources to be accessed over the network,
potentially enabling XXE or SSRF attacks. The new default behavior is
to treat all input as untrusted. The upstream advisory provides
further information how to mitigate the problem or restore the old
behavior again.

https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-vr8
q-g5c7-m54m

For Debian 9 stretch, this problem has been fixed in version
1.6.8.1-1+deb9u1.

We recommend that you upgrade your ruby-nokogiri packages.

For the detailed security status of ruby-nokogiri please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/ruby-nokogiri

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-vr8q-g5c7-m54m
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae52fb19"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ruby-nokogiri"
  );
  # https://security-tracker.debian.org/tracker/source-package/ruby-nokogiri
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4325c6e"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected ruby-nokogiri package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-nokogiri");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"ruby-nokogiri", reference:"1.6.8.1-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
