#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-384. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15221);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2003-0681", "CVE-2003-0694");
  script_bugtraq_id(8641, 8649);
  script_xref(name:"DSA", value:"384");

  script_name(english:"Debian DSA-384-1 : sendmail - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were reported in sendmail.

  - CAN-2003-0681 :
    A 'potential buffer overflow in ruleset parsing' for
    Sendmail 8.12.9, when using the nonstandard rulesets (1)
    recipient (2), final, or (3) mailer-specific envelope
    recipients, has unknown consequences.

  - CAN-2003-0694 :

    The prescan function in Sendmail 8.12.9 allows remote
    attackers to execute arbitrary code via buffer overflow
    attacks, as demonstrated using the parseaddr function in
    parseaddr.c."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-384"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) these problems have been fixed in
sendmail version 8.12.3-6.6 and sendmail-wide version
8.12.3+3.5Wbeta-5.5.

We recommend that you update your sendmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libmilter-dev", reference:"8.12.3-6.6")) flag++;
if (deb_check(release:"3.0", prefix:"sendmail", reference:"8.12.3-6.6")) flag++;
if (deb_check(release:"3.0", prefix:"sendmail-doc", reference:"8.12.3-6.6")) flag++;
if (deb_check(release:"3.0", prefix:"sendmail-wide", reference:"8.12.3+3.5Wbeta-5.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
