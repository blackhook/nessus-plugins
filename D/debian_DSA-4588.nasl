#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4588. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132110);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/16");

  script_cve_id("CVE-2019-14853", "CVE-2019-14859");
  script_xref(name:"DSA", value:"4588");

  script_name(english:"Debian DSA-4588-1 : python-ecdsa - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that python-ecdsa, a cryptographic signature library
for Python, incorrectly handled certain signatures. A remote attacker
could use this issue to cause python-ecdsa to either not warn about
incorrect signatures, or generate exceptions resulting in a
denial-of-service."
  );
  # https://security-tracker.debian.org/tracker/source-package/python-ecdsa
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e563916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python-ecdsa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/python-ecdsa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4588"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python-ecdsa packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 0.13-2+deb9u1.

For the stable distribution (buster), these problems have been fixed
in version 0.13-3+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14859");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ecdsa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"python-ecdsa", reference:"0.13-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"python3-ecdsa", reference:"0.13-3+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-ecdsa", reference:"0.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-ecdsa", reference:"0.13-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
