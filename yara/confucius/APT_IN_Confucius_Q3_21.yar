rule APT_IN_Confucius_Loader : Confucius_Q3_21 {
 
 meta:
	description = "Yara rule to detect the loader and in-memory execution module by Confucius"
	author = "Syed Hasan (@syedhasan009)"
	date = "2021-08-18"
	score = 65
	tlp = "white"
	status = "experimental"
 
 strings:
	// PDB path 
	$pdb1 = "F:\\Hacking Notes - Documents\\Projects\\project05\\SowpnTdb\\SowpnTdb\\bin\\Release\\ILMerge\\SowpnTdb.pdb"

	// Capabilities
	$f1 = "Reflection.Assembly" wide
	$f2 = "LoadFile" wide
	$f3 = "New-Object"
	$f4 = "Invoke"
	$f5 = "Enumerable"
	$f6 = "DownloadString"
	$f7 = "DownloadFile"
	$f8 = "GetTempPath"
	$f9 = "WebClient"
	$f10 = "Load"
	$f11 = "Create"
	$f12 = "Assembly"
	$f13 = "UploadFile"
	$f14 = "HttpWebRequest"

	// File Extensions
	$ext1 = ".txt" wide
	$ext2 = ".dll" wide
 
 condition:
	(any of ($ext*) or any of ($pdb*)) and
	5 of ($f*)
}


rule APT_IN_Confucius_Stealer : Confucius_Q3_21 {

 meta:
	description = "Yara rule to detect the stealer or uploaded used by Confucius in their espionage campaigns"
	author = "Syed Hasan (@syedhasan009)"
	date = "2021-10-15"
	score = 80
	tlp = "white"
	status = "experimental"
	
 strings:
	// Detects HTTP URLs used for exfiltration
	$r1 = /http:\/\/([0-9A-Za-z\/.]{10,30}.php)/ wide
	
	// Useful strings
	$s1 = "get_MachineName"
	$s2 = "get_UserName"
	$s3 = "pfhl"
	$s4 = "silly=./" wide
	$s5 = "sdsdjkfhds"
	$s6 = "Gpufh"
	$s7 = "&kusr=" wide
	
	// Generic strings
	$c1 = "01CSDLLHTTPFileUpload"
	$c2 = "Rwlksdnasjd"
	$c3 = "application/x-www-form-urlencoded" wide
	
	// File Extensions
	$e1 = "doc" nocase wide
	$e2 = "docx" nocase wide
	$e3 = "jpg" nocase wide
	$e4 = "jpeg" nocase wide
	$e5 = "pptx" nocase wide
	$e6s = "xlsm" nocase wide
	
 condition:
	$r1 and
	4 of ($s*) and
	1 of ($c*) and
	3 of ($e*) 
}
