#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1159. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22701);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-2779", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810");
  script_bugtraq_id(18228, 19181);
  script_xref(name:"CERT", value:"466673");
  script_xref(name:"CERT", value:"655892");
  script_xref(name:"CERT", value:"687396");
  script_xref(name:"CERT", value:"876420");
  script_xref(name:"CERT", value:"911004");
  script_xref(name:"DSA", value:"1159");

  script_name(english:"Debian DSA-1159-2 : mozilla-thunderbird - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The latest security updates of Mozilla Thunderbird introduced a
regression that led to a dysfunctional attachment panel which warrants
a correction to fix this issue. For reference please find below the
original advisory text :

  Several security related problems have been discovered in Mozilla
  and derived products such as Mozilla Thunderbird. The Common
  Vulnerabilities and Exposures project identifies the following
  vulnerabilities :

    - CVE-2006-2779
      Mozilla team members discovered several crashes during
      testing of the browser engine showing evidence of
      memory corruption which may also lead to the execution
      of arbitrary code. The last bit of this problem will
      be corrected with the next update. You can prevent any
      trouble by disabling JavaScript. [MFSA-2006-32]

    - CVE-2006-3805
      The JavaScript engine might allow remote attackers to
      execute arbitrary code. [MFSA-2006-50]

    - CVE-2006-3806
      Multiple integer overflows in the JavaScript engine
      might allow remote attackers to execute arbitrary
      code. [MFSA-2006-50]

    - CVE-2006-3807
      Specially crafted JavaScript allows remote attackers
      to execute arbitrary code. [MFSA-2006-51]

    - CVE-2006-3808
      Remote Proxy AutoConfig (PAC) servers could execute
      code with elevated privileges via a specially crafted
      PAC script. [MFSA-2006-52]

    - CVE-2006-3809
      Scripts with the UniversalBrowserRead privilege could
      gain UniversalXPConnect privileges and possibly
      execute code or obtain sensitive data. [MFSA-2006-53]

    - CVE-2006-3810
      A cross-site scripting vulnerability allows remote
      attackers to inject arbitrary web script or HTML.
      [MFSA-2006-54]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1159"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mozilla-thunderbird package.

For the stable distribution (sarge) these problems have been fixed in
version 1.0.2-2.sarge1.0.8b.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird", reference:"1.0.2-2.sarge1.0.8b.2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-dev", reference:"1.0.2-2.sarge1.0.8b.2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-inspector", reference:"1.0.2-2.sarge1.0.8b.2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-offline", reference:"1.0.2-2.sarge1.0.8b.2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-typeaheadfind", reference:"1.0.2-2.sarge1.0.8b.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
