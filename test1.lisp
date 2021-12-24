;; - This short program opens a pcap file and extracts some informations from each frame.
;; - It ist written in Common LISP.
;; - The program uses the "plokami" module to extract Ethernet frames from the pcap.
;;

(ql:quickload "plokami")
(use-package :plokami)
;;(find-all-devs)

(defun int2hex (int_value)
  "Convert a decimal value into a hexadecimal value. Currently only for Bytes (0-255)"
  ;; hexstr ist der hexadezimale Rückgabewert
  (let* ((hexstr (write-to-string int_value :base 16)   )
	 ;; Hexadezimalzahl ggfs. auf zwei Stellen erweitern	 
	 (l (length hexstr) ))
    (if (= 1 l)
        (setq hexstr  (concatenate 'string "0" hexstr)))
    hexstr
    ))

(with-pcap-reader (reader "test.pcapng" :snaplen 1500)
  "Read Frames from the file test.pcapng an extract L2 and L3 informations. "
  ;; Loop through all Frames in the pcap file
  (capture reader -1
           (lambda (sec usec caplen len buffer)
	     ;; 'buffer' contains the current frame.
	     ;; 
	     ;; Extract time and length informations
	     (princ ">")
	     (terpri)
	     (princ "Time index: ")
	     (princ sec)
	     (princ ".")
	     (princ usec)
	     (terpri)
	     (princ "Capture Length: ")
	     (princ caplen)
	     (terpri)
	     (princ "Length: ")
	     (princ len)
	     (terpri)
	     ;; Declare and assign variables
	     ;; Destination MAC address
	     (let* ((dst_mac  (concatenate 'string
					 (int2hex (aref buffer 0)) ":"
					 (int2hex (aref buffer 1)) ":"
					 (int2hex (aref buffer 2)) ":"
					 (int2hex (aref buffer 3)) ":"
					 (int2hex (aref buffer 4)) ":"
					   (int2hex (aref buffer 5)) ":"))
	     ;; Source MAC address
	     (src_mac  (concatenate 'string
					 (int2hex (aref buffer 6)) ":"
					 (int2hex (aref buffer 7)) ":"
					 (int2hex (aref buffer 8)) ":"
					 (int2hex (aref buffer 9)) ":"
					 (int2hex (aref buffer 10)) ":"
					 (int2hex (aref buffer 11)) ":"))
	     ;; Frame type
	     ( frame_type  (concatenate 'string
					    (int2hex (aref buffer 12)) (int2hex (aref buffer 13))))
		    ;; Declare variables for L3/L4
		    (ip_ver"")
		    (ihl 0)
		    (tos "")
		    (ip_len "")
		    (ip_id "")
		    (ip_off "")
		    (ip_ttl "")
		    (ip_p "")
		    (ip_sum "")
		    (ip_src "")
		    (ip_dst "")
		    (tcp_src "")
		    (tcp_dst "")
		    (tcp_seq "")
		    (tcp_ack "")
		    (tcp_off "")
		    (tcp_rsv "")
		    (tcp_flg "")
		    (tcp_wnd "")
		    (tcp_chk "")
		    (tcp_urg "")
		    )
	     ;; IP Version (4/6)
	     (setq ip_ver (int2hex (floor (aref buffer 14) 16)))
	     ;; IPv4 Initial header length
	     (setq ihl (* (mod (aref buffer 14) 16) 32))
	     ;; IPv4 Type of Service
	     (setq tos (int2hex(aref buffer 15)))
	     ;; IPv4 length
	     (setq ip_len  (concatenate 'string
					    (int2hex (aref buffer 16)) (int2hex (aref buffer 17))))
	     ;; IPv4 identification
	     (setq ip_id  (concatenate 'string
					    (int2hex (aref buffer 18)) (int2hex (aref buffer 19))))
	     ;; IPv4 offset
	     (setq ip_off  (concatenate 'string
					    (int2hex (aref buffer 20)) (int2hex (aref buffer 21))))
	     ;; IPv4 time-to-live
	     (setq ip_ttl (int2hex (aref buffer 22)))
	     ;; IPv4 L4 protocol (e. g. UDP, TCP) 
	     (setq ip_p (int2hex (aref buffer 23)))
	     ;; IPv4 Header checksum
	     (setq ip_sum  (concatenate 'string
					    (int2hex (aref buffer 24)) (int2hex (aref buffer 25))))
	     ;; IPv4 source address
	     (setq ip_src  (concatenate 'string
					    (write-to-string (aref buffer 26)) "." (write-to-string (aref buffer 27)) "." (write-to-string (aref buffer 28)) "."  (write-to-string (aref buffer 29))))
	     ;; IPv4 destination address
	     (setq ip_dst  (concatenate 'string
					(write-to-string (aref buffer 30)) "." (write-to-string (aref buffer 31)) "." (write-to-string (aref buffer 32)) "."  (write-to-string (aref buffer 33))))
	     ;; TCP source port
	     (setq tcp_src  (concatenate 'string
					    (int2hex (aref buffer 34)) (int2hex (aref buffer 35))))
	     ;; TCP destination port
	     (setq tcp_dst  (concatenate 'string
					    (int2hex (aref buffer 36)) (int2hex (aref buffer 37))))
	     ;; TCP sequence number
	     (setq tcp_seq  (concatenate 'string
					    (int2hex (aref buffer 38)) (int2hex (aref buffer 39))
					    (int2hex (aref buffer 40)) (int2hex (aref buffer 41)) ))
	     ;; TCP acknowledge number
	     (setq tcp_ack  (concatenate 'string
					    (int2hex (aref buffer 42)) (int2hex (aref buffer 43))
					    (int2hex (aref buffer 44)) (int2hex (aref buffer 45)) ))
	     ;; TCP offset
	     (setq tcp_off (int2hex (floor (aref buffer 46) 16)))
	     ;; TCP reserved
	     (setq tcp_rsv (int2hex (* (mod (aref buffer 46) 16) 32)))
	     ;; TCP flags
	     (setq tcp_flg (int2hex (aref buffer 47)))
	     ;; TCP window size
	     (setq tcp_wnd  (concatenate 'string
					    (int2hex (aref buffer 48)) (int2hex (aref buffer 49))))
	     ;; TCP checksum
	     (setq tcp_chk  (concatenate 'string
					    (int2hex (aref buffer 50)) (int2hex (aref buffer 51))))
	     ;; TCP urgent pointer
	     (setq tcp_urg  (concatenate 'string
					    (int2hex (aref buffer 52)) (int2hex (aref buffer 53))))
	     ;; next command doesn't work
	       ;(setq hashwert (sxhash (list 'list buffer)))
					;(princ hashwert)
	     ;; Print extracted informations
	     ;;(princ (concatenate  'string "*" src_mac " => " dst_mac " FT: " frame_type " IPv: " ip_ver " IHL: " (write-to-string ihl) " TOS: " tos " IPLEN: " ip_len " IPID: " ip_id " IPOFF: " ip_off " IPTTL: " ip_ttl " IPP: " ip_p " IPSUM: " ip_sum " IPSRC: " ip_src ":" tcp_src " IPDST: " ip_dst ":" tcp_dst " tcp_seq: " tcp_seq " tcp_ack: " tcp_ack " TCPOFF: " tcp_off " TCPRSV: " tcp_rsv " TCPFLG: " tcp_flg " TCPWND: " tcp_wnd " TCPCHK: " tcp_chk " TCPURG: " tcp_urg))
	       (terpri)
	       )
	     )))

