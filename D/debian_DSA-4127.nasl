#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4127. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107119);
  script_version("3.3");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-12867", "CVE-2017-12869", "CVE-2017-12873", "CVE-2017-12874", "CVE-2017-18121", "CVE-2017-18122", "CVE-2018-6519", "CVE-2018-6521", "CVE-2018-7644");
  script_xref(name:"DSA", value:"4127");

  script_name(english:"Debian DSA-4127-1 : simplesamlphp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in SimpleSAMLphp, a
framework for authentication, primarily via the SAML protocol.

  - CVE-2017-12867
    Attackers with access to a secret token could extend its
    validity period by manipulating the prepended time
    offset.

  - CVE-2017-12869
    When using the multiauth module, attackers can bypass
    authentication context restrictions and use any
    authentication source defined in the config.

  - CVE-2017-12873
    Defensive measures have been taken to prevent the
    administrator from misconfiguring persistent NameIDs to
    avoid identifier clash. (Affects Debian 8 Jessie only.)

  - CVE-2017-12874
    The InfoCard module could accept incorrectly signed XML
    messages in rare occasions.

  - CVE-2017-18121
    The consentAdmin module was vulnerable to a Cross-Site
    Scripting attack, allowing an attacker to craft links
    that could execute arbitrary JavaScript code in the
    victim's browser.

  - CVE-2017-18122
    The (deprecated) SAML 1.1 implementation would regard as
    valid any unsigned SAML response containing more than
    one signed assertion, provided that the signature of at
    least one of the assertions was valid, allowing an
    attacker that could obtain a valid signed assertion from
    an IdP to impersonate users from that IdP.

  - CVE-2018-6519
    Regular expression denial of service when parsing
    extraordinarily long timestamps.

  - CVE-2018-6521
    Change sqlauth module MySQL charset from utf8 to utf8mb
    to prevent theoretical query truncation that could allow
    remote attackers to bypass intended access restrictions

  - CVE-2018-7644
    Critical signature validation vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=889286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7644"
  );
  # https://security-tracker.debian.org/tracker/source-package/simplesamlphp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2a51c10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/simplesamlphp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/simplesamlphp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4127"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the simplesamlphp packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1.13.1-2+deb8u1.

For the stable distribution (stretch), these problems have been fixed
in version 1.14.11-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:simplesamlphp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"simplesamlphp", reference:"1.13.1-2+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"simplesamlphp", reference:"1.14.11-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
