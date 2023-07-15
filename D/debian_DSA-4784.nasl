#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4784. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142626);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2020-28032", "CVE-2020-28033", "CVE-2020-28034", "CVE-2020-28035", "CVE-2020-28036", "CVE-2020-28037", "CVE-2020-28038", "CVE-2020-28039", "CVE-2020-28040");
  script_xref(name:"DSA", value:"4784");

  script_name(english:"Debian DSA-4784-1 : wordpress - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in Wordpress, a web blogging
tool. They allowed remote attackers to run insecure deserialization,
embed spam, perform various Cross-Site Scripting (XSS) or Cross-Site
Request Forgery (CSRF) attacks, escalate privileges, run arbitrary
code, and delete arbitrary files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=971914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=973562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4784"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the wordpress packages.

For the stable distribution (buster), these problems have been fixed
in version 5.0.11+dfsg1-0+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28037");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"wordpress", reference:"5.0.11+dfsg1-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"wordpress-l10n", reference:"5.0.11+dfsg1-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"wordpress-theme-twentynineteen", reference:"5.0.11+dfsg1-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"wordpress-theme-twentyseventeen", reference:"5.0.11+dfsg1-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"wordpress-theme-twentysixteen", reference:"5.0.11+dfsg1-0+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
