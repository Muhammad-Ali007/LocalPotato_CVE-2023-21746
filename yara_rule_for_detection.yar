rule detect_localpotato {
    meta:
        description = "Detects the localpotato exploit"
    strings:
                $CLSID = "854A20FB-2D44-457D-992F-EF13785D2B51"
		$localpotato = {6c 6f 63 61 6c 70 6f 74 61 74 6f}
		$ntlm = {4e 54 4c 4d}
		$function = "NtQueryInformationProcess"

    condition:
        all of them
}