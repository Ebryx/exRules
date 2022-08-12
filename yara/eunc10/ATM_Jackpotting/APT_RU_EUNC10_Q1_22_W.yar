rule APT_RU_EUNC10_ATMDispenser : EUNC10_Q1_22 {
	
	meta:
		author = "Ahmad Muneeb Khan"
		date = "12-08-2022"
		description = "Detects the cash dispensing malware"
		score = 80
		tlp = "white"
		status = "experimental"
		reference = "https://www.group-ib.com/resources/threat-research/silence_2.0.going_global.pdf"
	
	strings:
		$file1 = { (6D 73 78 66 73 | 4D 53 58 46 53) 2E 64 6C 6C } //msxfs.dll
		$file2 = { 43 3A 5C 78 66 73 61 73 64 66 2E 74 78 74 } //C:\\xfsasdf.txt

		$api1 = { 57 46 53 4F 70 65 6E } //WFSOpen
		$api2 = { 57 46 53 47 65 74 49 6E 66 6F } //WFSGetInfo
		$api3 = { 57 46 53 4C 6F 63 6B } //WFSLock
		$api4 = { 57 46 53 45 78 65 63 75 74 65 } //WFSExecute

		$str1 = { (4F 00 70 00 65 00 72 00 61 00 74 00 6F | 44 00 69 00 73 00 70 00 65 00 6E 00 73) 00 72 00 20 00 70 00 61 00 6E 00 65 00 6C } //Operator or Dispense Panel
		$str2 = { 49 00 6E 00 70 00 75 00 74 00 20 00 50 00 49 00 4E 00 2D 00 63 00 6F 00 64 00 65 00 20 00 66 00 6F 00 72 00 20 00 61 00 63 00 63 00 65 00 73 00 73 } //Input PIN-code for access
		$str3 = { 53 00 61 00 6E 00 63 00 74 00 69 00 6F 00 6E 00 73 00 20 00 (47 | 67) 00 72 00 6F 00 75 00 70 } //Sanctions Group or group
		$str4 = { 50 72 6F 6A 65 63 74 20 41 6C 69 63 65 } //Project Alice
		$str5 = { 4E 43 52 41 70 70 2E 65 78 65 } //NCRApp.exe
		
		$pdb1 = "C:\\_bkittest\\dispenser\\Release_noToken\\dispenserXFS.pdb"
		$pdb2 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb"

	condition:
		uint16(0) == 0x5a4d and filesize >= 15KB and 1 of ($file*) and (3 of ($api*) and 2 of ($str*) or any of ($pdb*))

}
