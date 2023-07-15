#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4837. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(145319);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592");
  script_xref(name:"DSA", value:"4837");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0134");

  script_name(english:"Debian DSA-4837-1 : salt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in salt, a powerful remote
execution manager. The flaws could result in authentication bypass and
invocation of Salt SSH, creation of certificates with weak file
permissions via the TLS execution module or shell injections with the
Salt API using the SSH client."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/salt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/salt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4837"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the salt packages.

For the stable distribution (buster), these problems have been fixed
in version 2018.3.4+dfsg1-6+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25592");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt REST API Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"salt-api", reference:"2018.3.4+dfsg1-6+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"salt-cloud", reference:"2018.3.4+dfsg1-6+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"salt-common", reference:"2018.3.4+dfsg1-6+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"salt-doc", reference:"2018.3.4+dfsg1-6+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"salt-master", reference:"2018.3.4+dfsg1-6+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"salt-minion", reference:"2018.3.4+dfsg1-6+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"salt-proxy", reference:"2018.3.4+dfsg1-6+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"salt-ssh", reference:"2018.3.4+dfsg1-6+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"salt-syndic", reference:"2018.3.4+dfsg1-6+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
