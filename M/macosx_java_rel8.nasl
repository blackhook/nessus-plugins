#TRUSTED 98d940d22c925fc8e3d090c33ae8ce74a3b0de76a1a0416e6b29e09401c8b7ae98e3f06d0d7f4a37c284a5e7086bf3ab564c3364fda8c4c9473828e84062011df0c4c89779c582e028f5ba7213c5500ed1e6367d5b10a504f7b724f4027635f278b5d18bda25999cf8fde056891464bfc7288938c91bcb9c181cca85fb4d79c5e9e1cd0fdff4d912af0da424b1de5dcf59d2bb74f50d7d4fe5b82bab1fe2e626a5ebad90433521d1089e611988a951d9a781b69fa0a2fc8b73d89a10df54690ddd87afbf5c92cb8b580e47ddae6498232093789e851e55aa80a556fe6f988336c8eedec52137c521739baa9baae901e57a038ea67ee86c0fff6f06fa5ca51f54020001c68bf9e674b84c1fb821984633570d6fa6e90e15f31a723d227ae8c680b714386ccfa771f10df2ca8cfe6fc1cb8bea95ecd5353a54474a6bdf153a3199af1b379d8c96317d30aadecc740c9caf071634d003e34ca157b9795106b6d6afb560d06f6e844316f56b7e97ac5318eeb34d310f6ddff7d548ee5516402f3cebe35a46806cb84d4679fb3a1204f66b450b6abd9d5ac8b64a19e484e77876d5d4ebadba0872a727a6058c04cb10168306921ccf3d60f34864ad8aaef7e7aad0308fcfa1b59d7c5456b84f2ad532efcfb710a7517c4b893ea6f57b68b0ec9d9e20108a4a259e5f9d2caab7983ebe61cf0f4d01322eaf1b19346762067e0474d51d
#TRUST-RSA-SHA256 3e8736814ee5f85e26ef69d81b0ef6cd73e94a3845968c56168ad2e15e5d872b2bf2ae3e80934c82d610bcd02fb346cbcf61fe2ad02bed8dd765175eb8b16e4a3c9cadbce9f962d253b835365bc0d83c014e0ada185b833fe38dc65694acf58126654b67091c7a1d244550f7cbf69d4244737db23eff4d39f5ececc62db52e840fd4686d72b00310f262a8ffe06c485c4f9e2ff2a2bce3abf25ebfd226d905144fa79efd12569bb494d6c0195cf10a175cffd2eba54dc29eb0c1dcb9b0b1e26e9de362ce84b6a67e841561697ea82cd6a1490518c27c74925951b9f3b5328373f6292f33e9563144b8a67472f7e658bedb1ee17f080e70da05108a5e2714e5ad9b6ffdf46123366c8e5bd9f6faaccbb8c04ed8bf85b94465b980d67e663c69a169fedc2846e2e01964bc6f94052f6535664651342fa5db7167430f5f78483f4f3abc405f887e3158b28d9e0984250150dbd16d9c61cd032b0114315c1a97134b34adc1fd1a957e14997ac25868edfa78673ca19b6971b76619ea69eba15a1735bb8dbecf0987d25de597bcda6c09270a30c13a35a6f538915fd0425cc92d07ccfb24752c3e6f31827afe148811f17aa2fb238c5d531b107281c07c2b6843a74f37d26aca724792e32f2f9123bffce54d0333516a5b953510c2916fbcc7c8b4cf22a842e8461247dfb49dfcc266d732148c9bcbc761b67174e9ee7c1d5fbab03e
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35685);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5340",
    "CVE-2008-5342",
    "CVE-2008-5343"
  );
  script_bugtraq_id(32892);

  script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 8");
  script_summary(english:"Check for Java Release 8 on Mac OS X 10.4");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS X
older than release 8. 

The remote version of this software contains several security
vulnerabilities in Java Web Start and the Java Plug-in.  For instance,
they may allow untrusted Java Web Start applications and untrusted Java
applets to obtain elevated privileges.  If an attacker can lure a user
on the affected host into visiting a specially crafted web page with a
malicious Java applet, he could leverage these issues to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3436");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/Feb/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 8.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-5340");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(0);
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);


# Mac OS X 10.4.11 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 8\.11\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(0);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 11.8.2.
  if (
    ver[0] < 11 ||
    (
      ver[0] == 11 &&
      (
        ver[1] < 8 ||
        (ver[1] == 8 && ver[2] < 2)
      )
    )
  ) security_hole(0);
}
