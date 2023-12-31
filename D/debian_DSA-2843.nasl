#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2843. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71934);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-0978", "CVE-2014-1236");
  script_bugtraq_id(64674, 64737);
  script_xref(name:"DSA", value:"2843");

  script_name(english:"Debian DSA-2843-1 : graphviz - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two buffer overflow vulnerabilities were reported in Graphviz, a rich
collection of graph drawing tools. The Common Vulnerabilities and
Exposures project identifies the following issues :

  - CVE-2014-0978
    It was discovered that user-supplied input used in the
    yyerror() function in lib/cgraph/scan.l is not
    bound-checked before beeing copied into an
    insufficiently sized memory buffer. A context-dependent
    attacker could supply a specially crafted input file
    containing a long line to cause a stack-based buffer
    overlow, resulting in a denial of service (application
    crash) or potentially allowing the execution of
    arbitrary code.

  - CVE-2014-1236
    Sebastian Krahmer reported an overflow condition in the
    chkNum() function in lib/cgraph/scan.l that is triggered
    as the used regular expression accepts an arbitrary long
    digit list. With a specially crafted input file, a
    context-dependent attacker can cause a stack-based
    buffer overflow, resulting in a denial of service
    (application crash) or potentially allowing the
    execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=734745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/graphviz"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/graphviz"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-2843"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the graphviz packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 2.26.3-5+squeeze2.

For the stable distribution (wheezy), these problems have been fixed
in version 2.26.3-14+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"graphviz", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"graphviz-dev", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"graphviz-doc", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcdt4", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcgraph5", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgraph4", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgraphviz-dev", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-guile", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-lua", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-ocaml", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-perl", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-php5", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-python", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-ruby", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-tcl", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgvc5", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgvc5-plugins-gtk", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgvpr1", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpathplan4", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libxdot4", reference:"2.26.3-5+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"graphviz", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"graphviz-dev", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"graphviz-doc", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libcdt4", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libcgraph5", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraph4", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphviz-dev", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgv-guile", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgv-lua", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgv-perl", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgv-php5", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgv-python", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgv-ruby", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgv-tcl", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgvc5", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgvc5-plugins-gtk", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgvpr1", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpathplan4", reference:"2.26.3-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxdot4", reference:"2.26.3-14+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
