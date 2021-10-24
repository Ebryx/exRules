import "pe"

rule APT_IN_Sidewinder_Dropper : Sidewinder_Q2_20 {
	meta:
		author = "Ahmad Muneeb Khan, Syed Hasan"
		date = "09-04-2020"
		description = "Detects stage-1 JavaScript dropper"
        score = 70
		tlp = "white"
        status = "experimental"
	strings:
		$cnc1 = "o.pink" fullword
		$cnc2 = "o.Work" fullword
		$enum3 = "finally{window.close()" fullword
		$enum4 = "fileEnum" fullword
		$enum5 = "fileEnum.moveFirst()" fullword
		$enum6 = "GetFolder"
		$enum7 = "GetSpecialFolder"
		$com1 = "<script"
		$com2 = "javascript"
		$com3 = "</script>"
	condition:
		filesize >= 200KB and (1 of ($cnc*) and 2 of ($com*) and 3 of ($enum*))
}
