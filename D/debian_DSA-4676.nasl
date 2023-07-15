#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4676. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136372);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-17361", "CVE-2020-11651", "CVE-2020-11652");
  script_xref(name:"DSA", value:"4676");
  script_xref(name:"IAVA", value:"2020-A-0195-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0041");

  script_name(english:"Debian DSA-4676-1 : salt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in salt, a powerful remote
execution manager, which could result in retrieve of user tokens from
the salt master, execution of arbitrary commands on salt minions,
arbitrary directory access to authenticated users or arbitrary code
execution on salt-api hosts."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=949222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=959684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/salt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/salt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/salt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4676"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the salt packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 2016.11.2+ds-1+deb9u3.

For the stable distribution (buster), these problems have been fixed
in version 2018.3.4+dfsg1-6+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11651");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt Master/Minion Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"salt-api", reference:"2018.3.4+dfsg1-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"salt-cloud", reference:"2018.3.4+dfsg1-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"salt-common", reference:"2018.3.4+dfsg1-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"salt-doc", reference:"2018.3.4+dfsg1-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"salt-master", reference:"2018.3.4+dfsg1-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"salt-minion", reference:"2018.3.4+dfsg1-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"salt-proxy", reference:"2018.3.4+dfsg1-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"salt-ssh", reference:"2018.3.4+dfsg1-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"salt-syndic", reference:"2018.3.4+dfsg1-6+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"salt-api", reference:"2016.11.2+ds-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"salt-cloud", reference:"2016.11.2+ds-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"salt-common", reference:"2016.11.2+ds-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"salt-doc", reference:"2016.11.2+ds-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"salt-master", reference:"2016.11.2+ds-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"salt-minion", reference:"2016.11.2+ds-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"salt-proxy", reference:"2016.11.2+ds-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"salt-ssh", reference:"2016.11.2+ds-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"salt-syndic", reference:"2016.11.2+ds-1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
