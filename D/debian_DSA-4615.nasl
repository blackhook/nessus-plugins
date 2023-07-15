#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4615. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133418);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1930", "CVE-2020-1931");
  script_xref(name:"DSA", value:"4615");
  script_xref(name:"IAVA", value:"2020-A-0056-S");

  script_name(english:"Debian DSA-4615-1 : spamassassin - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in spamassassin, a Perl-based spam
filter using text analysis. Malicious rule or configuration files,
possibly downloaded from an updates server, could execute arbitrary
commands under multiple scenarios."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=950258"
  );
  # https://security-tracker.debian.org/tracker/source-package/spamassassin
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92e1b8a1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/spamassassin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/spamassassin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4615"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the spamassassin packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 3.4.2-1~deb9u3.

For the stable distribution (buster), these problems have been fixed
in version 3.4.2-1+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"sa-compile", reference:"3.4.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"spamassassin", reference:"3.4.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"spamc", reference:"3.4.2-1+deb10u2")) flag++;
if (deb_check(release:"9.0", prefix:"sa-compile", reference:"3.4.2-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"spamassassin", reference:"3.4.2-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"spamc", reference:"3.4.2-1~deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
