#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3942. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102449);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-11610");
  script_xref(name:"DSA", value:"3942");

  script_name(english:"Debian DSA-3942-1 : supervisor - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Calum Hutton reported that the XML-RPC server in supervisor, a system
for controlling process state, does not perform validation on
requested XML-RPC methods, allowing an authenticated client to send a
malicious XML-RPC request to supervisord that will run arbitrary shell
commands on the server as the same user as supervisord.

The vulnerability has been fixed by disabling nested namespace lookup
entirely. supervisord will now only call methods on the object
registered to handle XML-RPC requests and not any child objects it may
contain, possibly breaking existing setups. No publicly available
plugins are currently known that use nested namespaces. Plugins that
use a single namespace will continue to work as before. Details can be
found on the upstream issue at
https://github.com/Supervisor/supervisor/issues/964 ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=870187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Supervisor/supervisor/issues/964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/supervisor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/supervisor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3942"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the supervisor packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 3.0r1-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 3.3.1-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Supervisor XML-RPC Authenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:supervisor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"supervisor", reference:"3.0r1-1+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"supervisor", reference:"3.3.1-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"supervisor-doc", reference:"3.3.1-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
