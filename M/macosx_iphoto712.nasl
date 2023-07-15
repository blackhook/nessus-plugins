#TRUSTED 65530dddfa3e78a6ab67c4d54eda712d9c1fbf692ae064765653ff9084849aaf7028f41134de72261bf438b880bb9021e488b09e2122550d0258d837671299caac90d95824433e52754f8fd051c929b89bb0763883329462afba2e0ed0ec6c6faf8352246773909a3c8f2ee61f473c39d82a7ae7825faa549b347bbb9d1fc66e937941a4a89da3736ec1e4bac0dd94a8abbf3556aaacc66155669ca1a2003b12905c462dfde6d641a39e0873b6b097b0d5ac2d543e8934079f953d95cd0b3d19946fd0a0a53759e44ac846bb480486a5ed3b399fee5ce7033edf09f08240f12928a300773e849cc1ed4e7cdf2071b452478614dad15eb11192beeacc3a0e81cab3e25fee9057958750779c81da6815e98a3c63388ff4f6305858d6b137e00826b92ea91377029918bddebe33ac8d7ec0c4c785b426800856d7b3560d1e9a2806d9de89117d7aec1bdf853b0580ec710b578f7a5847c4fc22a70d1cde52edd11f6aff9281554e6f6a7583713c6bbc897829e1b17de889c6a4771f4d8b356a42e6285288e372c268b9c6bae2f47869ddf91aea9a216d95979231f059e5ba691cb71ecfc8358f93e2e4c280eacf5ac3a238460f6ce5308e22973922f11515964b1c595748b684a1288e9fda83cf1a141feec2b608ced53d39f875a1055b5cbbcb96d883b53958dc40d777216257bacb32197e1cf6242997271337a2fc04ae1572f6
#TRUST-RSA-SHA256 0d39bbbff0b42ce9aa95fa313af3e08c6798fe3d179bb1e71e3e306ede66d69c5e941505e18ffb0c45474d30da8516da46f763866ee23acefc71f0c95f2254d67878a7bdcec89972e7665ed4081c29a9a4f69e0731962c21cef46b804e9065c3e3a1a60276848769920b728b4087dc478b4a5fb357c672210471e96cc935dc96822a84b40ddd507565b663db8f5a035cdfcc6e8e64e9d28eeda23820a9a997f43d78951373e7de2e964747e177dd070972783ed75e37072385a5fc793cf38eed9df36be3122de23ecd0521c84e408f65b6b3fa9922ac1b0981fae972205d39a52f704507e074c4ed4c3978e2800257aef7afa04fb034b5ab8fa0e7f62c73c745aef5e3ae8a643f98366a7770ea5cd013779a3c9adbe3766a01d606cd59afa4138feeb443a8d795cec1f0802a32c27d6ae14588b62f7cc80ba95dabf284dce5f732489f4f2d230cc72d82f1333f1199ec107ca435d8fec1364ae09150186f03d87ab99e8e23e54b1beaf7f34ed9b12fdefd2a64a9c4b9dc4e7746abb7c247d21dbb6cd61696db7b83b3247cacc3b9ed334c2b37eb76909bc3ae4137557c57672e097986c6b439b5bef3104b893dd14655bf3fc3f5eee1eb9a4b3315fe64707fd902185627af8ef8d803a8776ea4b0654aa26bbef712e33707a1f3a0334891cc5a885183c6f766c837282844f555633569b225faec6c91ee8ce2006ef17fd039f2
#
# (C) Tenable Network Security, Inc.
#
#

include("compat.inc");

if (description)
{
  script_id(30201);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2008-0043");
  script_bugtraq_id(27636);

  script_name(english:"iPhoto < 7.1.2 Format String Vulnerability");
  script_summary(english:"Checks version of iPhoto");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by a
format string vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of iPhoto 7.1 older than version
7.1.2. Such versions are reportedly affected by a format string
vulnerability. If an attacker can trick a user on the affected host
into subscribing to a specially crafted photocast, these issues could
be leveraged to execute arbitrary code on the affected host subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307398");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Feb/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/support/downloads/iphoto712.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to iPhoto 7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2008-0043");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0043");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:iphoto");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("global_settings.inc");
include("macosx_func.inc");
include("misc_func.inc");
include("ssh_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

uname = get_kb_item("Host/uname");
if (!uname) exit(0);

if (egrep(pattern:"Darwin.*", string:uname))
{
  cmd = GetBundleVersionCmd(file:"iPhoto.app", path:"/Applications");
  if (islocalhost())
    version = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(0);

    version = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  if (version)
  {
    version = chomp(version);
    ver = split(version, sep:'.', keep:FALSE);

    #Prevent FPs if shell handler errors get mixed into results
    if(int(ver[0]) == 0 && ver[0] != "0") exit(1, "Failed to get the version of GarageBand.");

    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      ver[0] == 7 &&
      (
        ver[1] == 0 ||
        (ver[1] == 1 && ver[2] < 2)
      )
    )
    {
        report = string(
          "\n",
          "The remote version of iPhoto is ", version, ".\n"
        );
        security_hole(port:0, extra:report);
    }
  }
}
